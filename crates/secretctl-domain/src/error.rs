use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum DomainError {
    #[error("Invalid ID format: {0}")]
    InvalidId(String),

    #[error("Invalid origin: {0}")]
    InvalidOrigin(String),

    #[error("Invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        from: &'static str,
        to: &'static str,
    },

    #[error("Invalid action: {0}")]
    InvalidAction(String),

    #[error("Expired: {0}")]
    Expired(String),

    #[error("Exceeded maximum uses: {max}")]
    ExceededMaxUses { max: u32 },

    #[error("Epoch mismatch: expected {expected}, got {actual}")]
    EpochMismatch { expected: u64, actual: u64 },

    #[error("Origin mismatch: expected {expected}, got {actual}")]
    OriginMismatch { expected: String, actual: String },

    #[error("Session mismatch: expected {expected}, got {actual}")]
    SessionMismatch { expected: String, actual: String },

    #[error("Security invariant violation: {0}")]
    SecurityInvariantViolation(String),
}
