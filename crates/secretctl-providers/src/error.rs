use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("Secret not found for locator: {0}")]
    NotFound(String),

    #[error("OS keychain authentication error")]
    AuthenticationFailed,

    #[error("Provider unavailable: {0}")]
    Unavailable(String),

    #[error("Storage operation failed: {0}")]
    StorageFailed(String),

    #[error("Internal provider error: {0}")]
    Internal(String),
}
