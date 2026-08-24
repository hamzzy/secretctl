use async_trait::async_trait;
use secretctl_crypto::SecretBytes;
use secretctl_providers::{ProviderError, SecretProvider};

/// Reserved Linux provider surface. Native Secret Service support is
/// intentionally pending while the release target is macOS-only.
pub struct LinuxSecretServiceProvider;

impl LinuxSecretServiceProvider {
    pub fn new() -> Self {
        Self
    }

    pub fn with_service(_: impl Into<String>) -> Self {
        Self
    }
}

impl Default for LinuxSecretServiceProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretProvider for LinuxSecretServiceProvider {
    fn provider_name(&self) -> &'static str {
        "linux-secret-service"
    }

    async fn get_secret(&self, _: &str) -> Result<SecretBytes, ProviderError> {
        Err(pending())
    }

    async fn store_secret(&self, _: &str, _: &[u8]) -> Result<(), ProviderError> {
        Err(pending())
    }

    async fn delete_secret(&self, _: &str) -> Result<(), ProviderError> {
        Err(pending())
    }

    async fn exists(&self, _: &str) -> Result<bool, ProviderError> {
        Err(pending())
    }
}

fn pending() -> ProviderError {
    ProviderError::Unavailable(
        "Linux Secret Service support is pending; the current release target is macOS".into(),
    )
}
