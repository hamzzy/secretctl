use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Key generation error: {0}")]
    KeyGeneration(String),

    #[error("Signature error: {0}")]
    Signature(String),

    #[error("Decryption error")]
    DecryptionFailed,

    #[error("Encryption error: {0}")]
    EncryptionFailed(String),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("Session expired or rekey required")]
    SessionExpired,
}
