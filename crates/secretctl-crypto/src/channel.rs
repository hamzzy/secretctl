use crate::error::CryptoError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub struct SecureChannel {
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    tx_nonce: u64,
    rx_nonce: u64,
}

impl SecureChannel {
    pub fn new_client(shared_secret: &[u8; 32], salt: &[u8], info: &[u8]) -> Self {
        let (tx_key, rx_key) = Self::derive_directional_keys(shared_secret, salt, info);
        Self {
            tx_cipher: ChaCha20Poly1305::new(&Key::from_slice(&tx_key)),
            rx_cipher: ChaCha20Poly1305::new(&Key::from_slice(&rx_key)),
            tx_nonce: 0,
            rx_nonce: 0,
        }
    }

    pub fn new_server(shared_secret: &[u8; 32], salt: &[u8], info: &[u8]) -> Self {
        let (client_tx, client_rx) = Self::derive_directional_keys(shared_secret, salt, info);
        // Server transmits on client_rx, receives on client_tx
        Self {
            tx_cipher: ChaCha20Poly1305::new(&Key::from_slice(&client_rx)),
            rx_cipher: ChaCha20Poly1305::new(&Key::from_slice(&client_tx)),
            tx_nonce: 0,
            rx_nonce: 0,
        }
    }

    fn derive_directional_keys(
        shared_secret: &[u8; 32],
        salt: &[u8],
        info: &[u8],
    ) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
        let mut okm = [0u8; 64];
        hk.expand(info, &mut okm)
            .expect("64 bytes is valid HKDF output length");

        let mut tx_key = [0u8; 32];
        let mut rx_key = [0u8; 32];
        tx_key.copy_from_slice(&okm[0..32]);
        rx_key.copy_from_slice(&okm[32..64]);
        okm.zeroize();

        (tx_key, rx_key)
    }

    fn format_nonce(counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Self::format_nonce(self.tx_nonce);
        self.tx_nonce = self
            .tx_nonce
            .checked_add(1)
            .ok_or(CryptoError::SessionExpired)?;

        self.tx_cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Self::format_nonce(self.rx_nonce);
        let plaintext = self
            .rx_cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        self.rx_nonce = self
            .rx_nonce
            .checked_add(1)
            .ok_or(CryptoError::SessionExpired)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_channel_bidirectional() {
        let shared_secret = [42u8; 32];
        let salt = b"secretctl-test-salt";
        let info = b"secretctl-session-v1";

        let mut client = SecureChannel::new_client(&shared_secret, salt, info);
        let mut server = SecureChannel::new_server(&shared_secret, salt, info);

        // Client -> Server
        let client_msg = b"hello from client";
        let encrypted_c2s = client.encrypt(client_msg).unwrap();
        let decrypted_c2s = server.decrypt(&encrypted_c2s).unwrap();
        assert_eq!(decrypted_c2s, client_msg);

        // Server -> Client
        let server_msg = b"hello from server";
        let encrypted_s2c = server.encrypt(server_msg).unwrap();
        let decrypted_s2c = client.decrypt(&encrypted_s2c).unwrap();
        assert_eq!(decrypted_s2c, server_msg);

        // Replay attempt fails
        assert!(server.decrypt(&encrypted_c2s).is_err());
    }
}
