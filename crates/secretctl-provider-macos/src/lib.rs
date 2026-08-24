use async_trait::async_trait;
use secretctl_crypto::SecretBytes;
use secretctl_providers::{ProviderError, SecretProvider};

pub const DEFAULT_MACOS_SERVICE: &str = "secretctl";

pub struct MacOsKeychainProvider {
    service: String,
}

impl MacOsKeychainProvider {
    pub fn new() -> Self {
        Self {
            service: DEFAULT_MACOS_SERVICE.to_string(),
        }
    }

    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

impl Default for MacOsKeychainProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
#[async_trait]
impl SecretProvider for MacOsKeychainProvider {
    fn provider_name(&self) -> &'static str {
        "macos-keychain"
    }

    async fn get_secret(&self, locator: &str) -> Result<SecretBytes, ProviderError> {
        use security_framework::passwords::get_generic_password;

        let service = self.service.clone();
        let locator = locator.to_string();
        let password_bytes = tokio::task::spawn_blocking(move || {
            get_generic_password(&service, &locator).map_err(|error| match error.code() {
                -25300 => ProviderError::NotFound(locator),
                -25293 => ProviderError::AuthenticationFailed,
                _ => ProviderError::StorageFailed("macOS Keychain retrieval failed".to_string()),
            })
        })
        .await
        .map_err(|_| ProviderError::Internal("Keychain worker failed".to_string()))??;

        Ok(SecretBytes::new(password_bytes))
    }

    async fn store_secret(&self, locator: &str, secret: &[u8]) -> Result<(), ProviderError> {
        use security_framework::passwords::set_generic_password;

        let service = self.service.clone();
        let locator = locator.to_string();
        let secret = zeroize::Zeroizing::new(secret.to_vec());
        tokio::task::spawn_blocking(move || {
            set_generic_password(&service, &locator, &secret).map_err(|_| {
                ProviderError::StorageFailed("macOS Keychain storage failed".to_string())
            })
        })
        .await
        .map_err(|_| ProviderError::Internal("Keychain worker failed".to_string()))??;

        Ok(())
    }

    async fn delete_secret(&self, locator: &str) -> Result<(), ProviderError> {
        use security_framework::passwords::delete_generic_password;

        let service = self.service.clone();
        let locator = locator.to_string();
        tokio::task::spawn_blocking(move || {
            delete_generic_password(&service, &locator).map_err(|error| match error.code() {
                -25300 => ProviderError::NotFound(locator),
                _ => ProviderError::StorageFailed("macOS Keychain deletion failed".to_string()),
            })
        })
        .await
        .map_err(|_| ProviderError::Internal("Keychain worker failed".to_string()))??;

        Ok(())
    }

    async fn exists(&self, locator: &str) -> Result<bool, ProviderError> {
        use security_framework::passwords::get_generic_password;

        let service = self.service.clone();
        let locator = locator.to_string();
        tokio::task::spawn_blocking(move || match get_generic_password(&service, &locator) {
            Ok(_) => Ok(true),
            Err(e) if e.code() == -25300 => Ok(false),
            Err(_) => Err(ProviderError::StorageFailed(
                "macOS Keychain lookup failed".to_string(),
            )),
        })
        .await
        .map_err(|_| ProviderError::Internal("Keychain worker failed".to_string()))?
    }
}

#[cfg(not(target_os = "macos"))]
#[async_trait]
impl SecretProvider for MacOsKeychainProvider {
    fn provider_name(&self) -> &'static str {
        "macos-keychain-stub"
    }

    async fn get_secret(&self, locator: &str) -> Result<SecretBytes, ProviderError> {
        Err(ProviderError::Unavailable(format!(
            "macOS Keychain is not supported on this platform: {}",
            locator
        )))
    }

    async fn store_secret(&self, _locator: &str, _secret: &[u8]) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "macOS Keychain is not supported on this platform".to_string(),
        ))
    }

    async fn delete_secret(&self, _locator: &str) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "macOS Keychain is not supported on this platform".to_string(),
        ))
    }

    async fn exists(&self, _locator: &str) -> Result<bool, ProviderError> {
        Ok(false)
    }
}
