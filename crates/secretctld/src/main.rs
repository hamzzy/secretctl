use rand::RngCore;
use secretctl_crypto::KeyPair;
use secretctl_policy::{PolicyDocument, PolicyEvaluator};
#[cfg(target_os = "linux")]
use secretctl_provider_linux::LinuxSecretServiceProvider as PlatformSecretProvider;
#[cfg(target_os = "macos")]
use secretctl_provider_macos::MacOsKeychainProvider as PlatformSecretProvider;
#[cfg(target_os = "windows")]
use secretctl_provider_windows::WindowsCredentialManagerProvider as PlatformSecretProvider;
use secretctl_providers::SecretProvider;
use secretctl_store::SqliteStore;
use secretctld::{BrokerServer, BrokerState};
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!("starting secretctld daemon");

    let secretctl_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("secretctl");
    tokio::fs::create_dir_all(&secretctl_dir).await?;

    let db_path = secretctl_dir.join("secretctl.db");
    let store = SqliteStore::open(&db_path)?;
    store.validate_no_prohibited_persisted_keys()?;

    let provider = Arc::new(PlatformSecretProvider::new());
    let broker_key = if provider
        .exists("installation-signing-key")
        .await
        .unwrap_or(false)
    {
        let secret = provider.get_secret("installation-signing-key").await?;
        KeyPair::from_bytes(secret.as_bytes())?
    } else {
        tracing::info!("generating installation signing key in macOS Keychain");
        let keypair = KeyPair::generate();
        provider
            .store_secret("installation-signing-key", &keypair.to_bytes())
            .await?;
        let key_path = secretctl_dir.join("broker_key.pub");
        let _ = tokio::fs::write(&key_path, keypair.public_key_bytes()).await;
        keypair
    };

    let policy_path = secretctl_dir.join("policy.yaml");
    let policy = if policy_path.exists() {
        let content = tokio::fs::read_to_string(&policy_path).await?;
        PolicyDocument::from_yaml(&content)?
    } else {
        // A missing policy is intentionally default-deny.
        PolicyDocument {
            version: "1.0".to_string(),
            rules: vec![],
        }
    };
    let evaluator = PolicyEvaluator::new(policy);

    let signing_key_id = store
        .active_signing_key_id()?
        .unwrap_or_else(|| "broker-key-v1".to_string());
    if store.active_signing_key_id()?.is_none() {
        store.register_signing_key(&signing_key_id, &broker_key.public_key_bytes(), "active")?;
    }
    let (audit_key_version, audit_key_locator) = store
        .active_audit_key_version()?
        .unwrap_or_else(|| (1, "audit-chain-key-v1".to_string()));
    let audit_key = if provider.exists(&audit_key_locator).await? {
        provider.get_secret(&audit_key_locator).await?
    } else {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        provider.store_secret(&audit_key_locator, &bytes).await?;
        let key = secretctl_crypto::SecretBytes::new(bytes.to_vec());
        bytes.fill(0);
        key
    };
    if store.active_audit_key_version()?.is_none() {
        store.register_audit_key_version(audit_key_version, &audit_key_locator, "active")?;
    }
    let state = BrokerState::try_new_with_audit_key(
        broker_key,
        signing_key_id,
        audit_key,
        audit_key_version,
        store,
        provider,
        evaluator,
    )?;

    let recipes_dir = secretctl_dir.join("recipes");
    if recipes_dir.exists() {
        let mut entries = tokio::fs::read_dir(&recipes_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let content = tokio::fs::read_to_string(&path).await?;
            validate_recipe_metadata_keys(&serde_json::from_str(&content)?, "$recipe")?;
            let mut recipe: secretctl_domain::SiteRecipe = serde_json::from_str(&content)?;
            let valid_field_count = if recipe.action == secretctl_domain::ActionKind::OAuthAuthorize
            {
                recipe.fields.is_empty() && recipe.oauth.is_some()
            } else {
                (1..=5).contains(&recipe.fields.len()) && recipe.oauth.is_none()
            };
            anyhow::ensure!(
                valid_field_count,
                "recipe {} must declare OAuth configuration with no fields, or 1 to 5 fields without OAuth configuration",
                path.display()
            );
            anyhow::ensure!(
                recipe.fields.iter().all(|field| {
                    !field.role.is_empty()
                        && field.role.len() <= 64
                        && !field.selector.trim().is_empty()
                }),
                "recipe {} contains an invalid field role or selector",
                path.display()
            );
            anyhow::ensure!(
                recipe
                    .match_rule
                    .path_prefix
                    .as_ref()
                    .is_none_or(|prefix| prefix.starts_with('/')),
                "recipe {} path_prefix must begin with '/'",
                path.display()
            );
            recipe.content_hash = secretctl_crypto::sha256_digest(content.as_bytes()).to_vec();
            state.register_recipe(recipe);
        }
    }

    let runtime_dir = secretctl_dir.join("run");
    let server = BrokerServer::new(state.clone(), runtime_dir.clone());

    server.start().await?;

    tracing::info!(?runtime_dir, "secretctld daemon started");

    tokio::signal::ctrl_c().await?;
    state
        .write_audit_checkpoint()
        .map_err(|error| anyhow::anyhow!(error.message))?;
    tracing::info!("secretctld shutting down");
    Ok(())
}

fn validate_recipe_metadata_keys(value: &serde_json::Value, path: &str) -> anyhow::Result<()> {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                anyhow::ensure!(
                    !secretctl_crypto::contains_prohibited_key_name(key),
                    "prohibited secret-bearing recipe key at {path}.{key}"
                );
                validate_recipe_metadata_keys(value, &format!("{path}.{key}"))?;
            }
        }
        serde_json::Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                validate_recipe_metadata_keys(value, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}
