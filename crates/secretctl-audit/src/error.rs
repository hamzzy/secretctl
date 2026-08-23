use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Hash chain verification failed at sequence {sequence}")]
    ChainBroken { sequence: u64 },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Prohibited key in audit payload: {0}")]
    ProhibitedPayload(String),
}
