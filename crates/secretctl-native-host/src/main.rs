use clap::{Parser, Subcommand};
use secretctl_crypto::KeyPair;
use secretctl_domain::{AgentId, AgentPrincipal};
use secretctl_native_host::{NativeHostManifest, run_stdio_bridge};
#[cfg(target_os = "linux")]
use secretctl_provider_linux::LinuxSecretServiceProvider as PlatformSecretProvider;
#[cfg(target_os = "macos")]
use secretctl_provider_macos::MacOsKeychainProvider as PlatformSecretProvider;
#[cfg(target_os = "windows")]
use secretctl_provider_windows::WindowsCredentialManagerProvider as PlatformSecretProvider;
use secretctl_providers::SecretProvider;
use secretctl_store::SqliteStore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "secretctl-native-host",
    about = "Chrome Native Messaging Host for secretctl"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Install the exact-origin manifest and enroll this executable.
    Install {
        #[arg(long, default_value = secretctl_protocol::MANAGED_EXTENSION_ID)]
        extension_id: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostConfig {
    principal_id: AgentId,
    extension_id: String,
    #[serde(default)]
    key_locator: String,
}

fn secretctl_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("secretctl")
}

async fn load_config(path: &Path) -> anyhow::Result<HostConfig> {
    Ok(secretctl_protocol::from_slice_strict(
        &tokio::fs::read(path).await?,
    )?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Chrome supplies the caller origin as argv[1]. Handle that invocation
    // before clap so Chromium's platform-specific trailing arguments cannot be
    // mistaken for user-facing CLI flags.
    if let Some(caller_origin) = std::env::args()
        .nth(1)
        .filter(|arg| arg.starts_with("chrome-extension://"))
    {
        let dir = secretctl_dir();
        let config = load_config(&dir.join("native-host.json")).await?;
        anyhow::ensure!(
            caller_origin == format!("chrome-extension://{}/", config.extension_id),
            "native messaging caller origin rejected"
        );
        let provider = PlatformSecretProvider::new();
        let key_locator = if config.key_locator.is_empty() {
            format!("native-host-signing-{}", config.principal_id)
        } else {
            config.key_locator.clone()
        };
        let key = provider.get_secret(&key_locator).await?;
        let signing_key = KeyPair::from_bytes(key.as_bytes())?;
        let broker_public_key = tokio::fs::read(dir.join("broker_key.pub")).await?;
        anyhow::ensure!(
            broker_public_key.len() == 32,
            "invalid broker public-key pin"
        );
        run_stdio_bridge(
            dir.join("run/executor.sock"),
            config.principal_id.as_str(),
            &signing_key,
            &broker_public_key,
            dir.join("extension-enrollment.json"),
        )
        .await?;
        return Ok(());
    }

    match Cli::parse().command {
        Some(Commands::Install { extension_id }) => {
            anyhow::ensure!(
                extension_id == secretctl_protocol::MANAGED_EXTENSION_ID,
                "only the packaged secretctl extension ID may be enrolled"
            );
            let dir = secretctl_dir();
            tokio::fs::create_dir_all(&dir).await?;
            let config_path = dir.join("native-host.json");
            let prior = if config_path.exists() {
                Some(load_config(&config_path).await?)
            } else {
                None
            };
            let principal_id = prior
                .as_ref()
                .map(|config| config.principal_id.clone())
                .unwrap_or_else(AgentId::new);
            let key_locator = prior
                .map(|config| config.key_locator)
                .filter(|locator| !locator.is_empty())
                .unwrap_or_else(|| format!("native-host-signing-{principal_id}"));
            let provider = PlatformSecretProvider::new();
            let signing_key = if provider.exists(&key_locator).await? {
                let secret = provider.get_secret(&key_locator).await?;
                KeyPair::from_bytes(secret.as_bytes())?
            } else {
                let key = KeyPair::generate();
                provider.store_secret(&key_locator, &key.to_bytes()).await?;
                key
            };
            let executable = tokio::fs::canonicalize(std::env::current_exe()?).await?;
            let executable_bytes = tokio::fs::read(&executable).await?;
            #[cfg(unix)]
            let peer_uid = {
                use std::os::unix::fs::MetadataExt;
                Some(std::fs::metadata(&dir)?.uid())
            };
            #[cfg(not(unix))]
            let peer_uid = None;
            let store = SqliteStore::open(dir.join("secretctl.db"))?;
            store.upsert_agent(&AgentPrincipal {
                agent_id: principal_id.clone(),
                role: "executor".to_string(),
                public_key: signing_key.public_key_bytes().to_vec(),
                display_name: "secretctl packaged native host".to_string(),
                peer_uid,
                executable_path: Some(executable.to_string_lossy().into_owned()),
                executable_hash: Some(secretctl_crypto::sha256_digest(&executable_bytes).to_vec()),
                state: "enrolled".to_string(),
                created_at: chrono::Utc::now(),
            })?;
            let config = HostConfig {
                principal_id,
                extension_id: extension_id.clone(),
                key_locator,
            };
            tokio::fs::write(&config_path, serde_json::to_vec_pretty(&config)?).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
            }
            let manifest = NativeHostManifest::new(executable, &extension_id);
            let installed_at = manifest.install(None).await?;
            let enrollment_path = dir.join("extension-enrollment.json");
            let enrollment = if enrollment_path.exists() {
                secretctl_protocol::from_slice_strict::<
                    secretctl_native_host::enrollment::ExtensionEnrollment,
                >(&tokio::fs::read(&enrollment_path).await?)?
            } else {
                secretctl_native_host::enrollment::ExtensionEnrollment::new(extension_id.clone())
            };
            tokio::fs::write(&enrollment_path, serde_json::to_vec_pretty(&enrollment)?).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&enrollment_path, std::fs::Permissions::from_mode(0o600))?;
            }
            println!(
                "Installed native messaging manifest to {}",
                installed_at.display()
            );
            if let Some(code) = enrollment.pending_pairing_code {
                println!("Pairing code: {code}");
                println!("Confirm that the extension popup shows the same code.");
            }
        }
        None => anyhow::bail!("native host must be invoked by the enrolled Chrome extension"),
    }
    Ok(())
}
