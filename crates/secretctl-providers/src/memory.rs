use crate::error::ProviderError;
use crate::traits::SecretProvider;
use async_trait::async_trait;
use secretctl_crypto::SecretBytes;
use std::collections::HashMap;
use std::sync::RwLock;

pub struct MemorySecretProvider {
    store: RwLock<HashMap<String, Vec<u8>>>,
}

impl MemorySecretProvider {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemorySecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretProvider for MemorySecretProvider {
    fn provider_name(&self) -> &'static str {
        "memory"
    }

    async fn get_secret(&self, locator: &str) -> Result<SecretBytes, ProviderError> {
        let store = self
            .store
            .read()
            .map_err(|_| ProviderError::Internal("Lock poisoned".to_string()))?;
        let bytes = store
            .get(locator)
            .cloned()
            .ok_or_else(|| ProviderError::NotFound(locator.to_string()))?;
        Ok(SecretBytes::new(bytes))
    }

    async fn store_secret(&self, locator: &str, secret: &[u8]) -> Result<(), ProviderError> {
        let mut store = self
            .store
            .write()
            .map_err(|_| ProviderError::Internal("Lock poisoned".to_string()))?;
        store.insert(locator.to_string(), secret.to_vec());
        Ok(())
    }

    async fn delete_secret(&self, locator: &str) -> Result<(), ProviderError> {
        let mut store = self
            .store
            .write()
            .map_err(|_| ProviderError::Internal("Lock poisoned".to_string()))?;
        store.remove(locator);
        Ok(())
    }

    async fn exists(&self, locator: &str) -> Result<bool, ProviderError> {
        let store = self
            .store
            .read()
            .map_err(|_| ProviderError::Internal("Lock poisoned".to_string()))?;
        Ok(store.contains_key(locator))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_provider_operations() {
        let provider = MemorySecretProvider::new();
        let locator = "github_password_user1";

        assert!(!provider.exists(locator).await.unwrap());

        provider
            .store_secret(locator, b"my_super_secret")
            .await
            .unwrap();
        assert!(provider.exists(locator).await.unwrap());

        let secret = provider.get_secret(locator).await.unwrap();
        assert_eq!(secret.as_bytes(), b"my_super_secret");

        provider.delete_secret(locator).await.unwrap();
        assert!(!provider.exists(locator).await.unwrap());
    }
}
