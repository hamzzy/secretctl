use crate::error::ProviderError;
use async_trait::async_trait;
use secretctl_crypto::SecretBytes;

#[async_trait]
pub trait SecretProvider: Send + Sync {
    fn provider_name(&self) -> &'static str;

    async fn get_secret(&self, locator: &str) -> Result<SecretBytes, ProviderError>;

    async fn store_secret(&self, locator: &str, secret: &[u8]) -> Result<(), ProviderError>;

    async fn delete_secret(&self, locator: &str) -> Result<(), ProviderError>;

    async fn exists(&self, locator: &str) -> Result<bool, ProviderError>;
}
