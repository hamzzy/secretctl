use async_trait::async_trait;
use secretctl_crypto::SecretBytes;
use secretctl_providers::{ProviderError, SecretProvider};

pub struct WindowsCredentialManagerProvider {
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    service: String,
}

impl WindowsCredentialManagerProvider {
    pub fn new() -> Self {
        Self {
            service: std::env::var("SECRETCTL_PROVIDER_SERVICE")
                .unwrap_or_else(|_| "secretctl".into()),
        }
    }
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

impl Default for WindowsCredentialManagerProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
#[async_trait]
impl SecretProvider for WindowsCredentialManagerProvider {
    fn provider_name(&self) -> &'static str {
        "windows-credential-manager"
    }
    async fn get_secret(&self, locator: &str) -> Result<SecretBytes, ProviderError> {
        let service = self.service.clone();
        let locator = locator.to_owned();
        let value = tokio::task::spawn_blocking(move || {
            keyring::Entry::new(&service, &locator)?.get_secret()
        })
        .await
        .map_err(|_| ProviderError::Internal("credential worker failed".into()))?
        .map_err(map_error)?;
        Ok(SecretBytes::new(value))
    }
    async fn store_secret(&self, locator: &str, secret: &[u8]) -> Result<(), ProviderError> {
        let service = self.service.clone();
        let locator = locator.to_owned();
        let secret = zeroize::Zeroizing::new(secret.to_vec());
        tokio::task::spawn_blocking(move || {
            keyring::Entry::new(&service, &locator)?.set_secret(&secret)
        })
        .await
        .map_err(|_| ProviderError::Internal("credential worker failed".into()))?
        .map_err(map_error)
    }
    async fn delete_secret(&self, locator: &str) -> Result<(), ProviderError> {
        let service = self.service.clone();
        let locator = locator.to_owned();
        tokio::task::spawn_blocking(move || {
            keyring::Entry::new(&service, &locator)?.delete_credential()
        })
        .await
        .map_err(|_| ProviderError::Internal("credential worker failed".into()))?
        .map_err(map_error)
    }
    async fn exists(&self, locator: &str) -> Result<bool, ProviderError> {
        match self.get_secret(locator).await {
            Ok(_) => Ok(true),
            Err(ProviderError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "windows")]
fn map_error(error: keyring::Error) -> ProviderError {
    match error {
        keyring::Error::NoEntry => ProviderError::NotFound("credential".into()),
        _ => ProviderError::StorageFailed("Windows Credential Manager operation failed".into()),
    }
}

#[cfg(not(target_os = "windows"))]
#[async_trait]
impl SecretProvider for WindowsCredentialManagerProvider {
    fn provider_name(&self) -> &'static str {
        "windows-credential-manager"
    }
    async fn get_secret(&self, _: &str) -> Result<SecretBytes, ProviderError> {
        Err(ProviderError::Unavailable(
            "Windows Credential Manager is unavailable on this platform".into(),
        ))
    }
    async fn store_secret(&self, _: &str, _: &[u8]) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "Windows Credential Manager is unavailable on this platform".into(),
        ))
    }
    async fn delete_secret(&self, _: &str) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "Windows Credential Manager is unavailable on this platform".into(),
        ))
    }
    async fn exists(&self, _: &str) -> Result<bool, ProviderError> {
        Err(ProviderError::Unavailable(
            "Windows Credential Manager is unavailable on this platform".into(),
        ))
    }
}
