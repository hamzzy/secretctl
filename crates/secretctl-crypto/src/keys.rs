use crate::error::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        key_bytes.zeroize();
        Ok(Self { signing_key })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

pub fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    if public_key_bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: public_key_bytes.len(),
        });
    }
    if signature_bytes.len() != 64 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 64,
            actual: signature_bytes.len(),
        });
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(public_key_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(&pk_arr).map_err(|e| CryptoError::Signature(e.to_string()))?;

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(message, &signature)
        .map_err(|e| CryptoError::Signature(e.to_string()))
}

pub struct EphemeralX25519 {
    secret: EphemeralSecret,
    public: XPublicKey,
}

impl EphemeralX25519 {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let public = XPublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn diffie_hellman(self, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
        let peer_public = XPublicKey::from(*peer_public_bytes);
        let shared = self.secret.diffie_hellman(&peer_public);
        *shared.as_bytes()
    }
}

impl Default for EphemeralX25519 {
    fn default() -> Self {
        Self::new()
    }
}

pub struct StaticX25519 {
    secret: StaticSecret,
}

impl StaticX25519 {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        Self { secret }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        let public = XPublicKey::from(&self.secret);
        *public.as_bytes()
    }

    pub fn diffie_hellman(&self, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
        let peer_public = XPublicKey::from(*peer_public_bytes);
        let shared = self.secret.diffie_hellman(&peer_public);
        *shared.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let kp = KeyPair::generate();
        let msg = b"secretctl test authentication message";
        let sig = kp.sign(msg);
        assert!(verify_signature(&kp.public_key_bytes(), msg, &sig).is_ok());

        let invalid_msg = b"corrupted message";
        assert!(verify_signature(&kp.public_key_bytes(), invalid_msg, &sig).is_err());
    }

    #[test]
    fn test_x25519_key_exchange() {
        let alice = EphemeralX25519::new();
        let bob = EphemeralX25519::new();

        let alice_pub = alice.public_bytes();
        let bob_pub = bob.public_bytes();

        let shared_alice = alice.diffie_hellman(&bob_pub);
        let shared_bob = bob.diffie_hellman(&alice_pub);

        assert_eq!(shared_alice, shared_bob);
    }
}
