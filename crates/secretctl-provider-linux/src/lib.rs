use async_trait::async_trait;
use secretctl_crypto::SecretBytes;
use secretctl_providers::{ProviderError, SecretProvider};

pub struct LinuxSecretServiceProvider {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    service: String,
}

impl LinuxSecretServiceProvider {
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
impl Default for LinuxSecretServiceProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl SecretProvider for LinuxSecretServiceProvider {
    fn provider_name(&self) -> &'static str {
        "linux-secret-service"
    }
    async fn get_secret(&self, locator: &str) -> Result<SecretBytes, ProviderError> {
        validate_attribute(&self.service)?;
        validate_attribute(locator)?;
        let output = tokio::process::Command::new("secret-tool")
            .args([
                "lookup",
                "service",
                self.service.as_str(),
                "locator",
                locator,
            ])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .map_err(map_spawn_error)?;
        if !output.status.success() {
            return Err(ProviderError::NotFound("credential".into()));
        }
        let mut value = output.stdout;
        if value.last() == Some(&b'\n') {
            value.pop();
            if value.last() == Some(&b'\r') {
                value.pop();
            }
        }
        Ok(SecretBytes::new(value))
    }
    async fn store_secret(&self, locator: &str, secret: &[u8]) -> Result<(), ProviderError> {
        use tokio::io::AsyncWriteExt as _;

        validate_attribute(&self.service)?;
        validate_attribute(locator)?;
        let label = format!("secretctl credential {locator}");
        let mut child = tokio::process::Command::new("secret-tool")
            .args([
                "store",
                "--label",
                label.as_str(),
                "service",
                self.service.as_str(),
                "locator",
                locator,
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(map_spawn_error)?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            ProviderError::Internal("secret-tool stdin unavailable".into())
        })?;
        stdin
            .write_all(secret)
            .await
            .map_err(|_| ProviderError::StorageFailed("Secret Service write failed".into()))?;
        stdin
            .shutdown()
            .await
            .map_err(|_| ProviderError::StorageFailed("Secret Service write failed".into()))?;
        let status = child
            .wait()
            .await
            .map_err(|_| ProviderError::StorageFailed("Secret Service write failed".into()))?;
        if status.success() {
            Ok(())
        } else {
            Err(ProviderError::StorageFailed(
                "Secret Service write failed".into(),
            ))
        }
    }
    async fn delete_secret(&self, locator: &str) -> Result<(), ProviderError> {
        validate_attribute(&self.service)?;
        validate_attribute(locator)?;
        let status = tokio::process::Command::new("secret-tool")
            .args([
                "clear",
                "service",
                self.service.as_str(),
                "locator",
                locator,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map_err(map_spawn_error)?;
        if status.success() {
            Ok(())
        } else {
            Err(ProviderError::NotFound("credential".into()))
        }
    }
    async fn exists(&self, locator: &str) -> Result<bool, ProviderError> {
        match self.get_secret(locator).await {
            Ok(_) => Ok(true),
            Err(ProviderError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_attribute(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        Err(ProviderError::StorageFailed(
            "Secret Service attribute is invalid".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn map_spawn_error(error: std::io::Error) -> ProviderError {
    if error.kind() == std::io::ErrorKind::NotFound {
        ProviderError::Unavailable("secret-tool is not installed".into())
    } else {
        ProviderError::Unavailable("Secret Service is unavailable".into())
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl SecretProvider for LinuxSecretServiceProvider {
    fn provider_name(&self) -> &'static str {
        "linux-secret-service"
    }
    async fn get_secret(&self, _: &str) -> Result<SecretBytes, ProviderError> {
        Err(ProviderError::Unavailable(
            "Linux Secret Service is unavailable on this platform".into(),
        ))
    }
    async fn store_secret(&self, _: &str, _: &[u8]) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "Linux Secret Service is unavailable on this platform".into(),
        ))
    }
    async fn delete_secret(&self, _: &str) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "Linux Secret Service is unavailable on this platform".into(),
        ))
    }
    async fn exists(&self, _: &str) -> Result<bool, ProviderError> {
        Err(ProviderError::Unavailable(
            "Linux Secret Service is unavailable on this platform".into(),
        ))
    }
}
