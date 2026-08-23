use thiserror::Error;

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("Capability token expired: {0}")]
    Expired(String),

    #[error("Capability token signature invalid")]
    InvalidSignature,

    #[error("Capability already consumed or exceeded max uses (max: {max}, used: {used})")]
    AlreadyConsumed { max: u32, used: u32 },

    #[error("Capability revoked: {0}")]
    Revoked(String),

    #[error("Binding mismatch: {field} expected {expected}, got {actual}")]
    BindingMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error("Navigation epoch mismatch: expected {expected}, got {actual}")]
    EpochMismatch { expected: u64, actual: u64 },

    #[error("Serialization error: {0}")]
    Serialization(String),
}
