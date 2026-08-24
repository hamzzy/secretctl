use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("CDP command denied: {0}")]
    CommandDenied(String),

    #[error("CDP command blocked during sensitive window: {0}")]
    SensitiveWindowBlocked(String),

    #[error("Browser launch error: {0}")]
    LaunchFailed(String),

    #[error("Browser process terminated unexpectedly")]
    ProcessTerminated,

    #[error("Private CDP transport error: {0}")]
    Transport(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
