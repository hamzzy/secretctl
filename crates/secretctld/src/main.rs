use secretctl_crypto::KeyPair;
use secretctl_policy::{PolicyDocument, PolicyEvaluator};
use secretctl_provider_macos::MacOsKeychainProvider;
use secretctl_providers::SecretProvider;
use secretctl_store::SqliteStore;
use secretctld::{BrokerServer, BrokerState};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting secretctld daemon...");

    let home_dir = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let secretctl_dir = PathBuf::from(home_dir).join(".secretctl");
    tokio::fs::create_dir_all(&secretctl_dir).await?;

    let db_path = secretctl_dir.join("secretctl.db");
    let store = SqliteStore::open(&db_path)?;

    let provider = Arc::new(MacOsKeychainProvider::new());
    let broker_key = if provider.exists("installation-signing-key").await.unwrap_or(false) {
        let secret = provider.get_secret("installation-signing-key").await?;
        KeyPair::from_bytes(secret.as_bytes())?
    } else {
        info!("No installation signing key found. Generating a new key in macOS Keychain...");
        let keypair = KeyPair::generate();
        provider
            .store_secret("installation-signing-key", &keypair.to_bytes())
            .await?;
        let key_path = secretctl_dir.join("broker_key.pub");
        let _ = tokio::fs::write(&key_path, keypair.public_key_bytes()).await;
        keypair
    };

    let default_policy = PolicyDocument {
        version: "1.0".to_string(),
        rules: vec![],
    };
    let evaluator = PolicyEvaluator::new(default_policy);

    let state = BrokerState::new(broker_key, "broker-key-default", store, provider, evaluator);
    let runtime_dir = secretctl_dir.join("run");
    let server = BrokerServer::new(state, runtime_dir);

    server.start().await?;

    info!("secretctld daemon started successfully.");
    tokio::signal::ctrl_c().await?;
    info!("secretctld shutting down.");
    Ok(())
}
