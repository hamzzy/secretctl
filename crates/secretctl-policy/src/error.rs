use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy parse error: {0}")]
    Parse(String),

    #[error("Invalid policy version: {0}")]
    InvalidVersion(String),

    #[error("Rule evaluation error: {0}")]
    Evaluation(String),

    #[error("No matching policy rule found (default deny)")]
    DefaultDeny,

    #[error("Origin does not match allowed destination: {0}")]
    OriginMismatch(String),

    #[error("Browser assurance level insufficient: required {required}, got {actual}")]
    AssuranceInsufficient { required: String, actual: String },
}
