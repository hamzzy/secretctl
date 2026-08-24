use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use rand::RngCore;
use secretctl_audit::verify_audit_chain;
use secretctl_crypto::KeyPair;
use secretctl_domain::{
    ActionKind, AgentId, AgentPrincipal, CanonicalOrigin, CredentialDescriptor, CredentialId,
};
use secretctl_policy::PolicyDocument;
use secretctl_provider_macos::MacOsKeychainProvider;
use secretctl_providers::SecretProvider;
use secretctl_store::SqliteStore;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "secretctl",
    version,
    about = "Local-first credential isolation for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize local secretctl installation
    Init,
    /// Manage agent principals
    Agent {
        #[command(subcommand)]
        cmd: AgentCommands,
    },
    /// Manage credentials
    Credential {
        #[command(subcommand)]
        cmd: CredentialCommands,
    },
    /// Manage site recipes
    Recipe {
        #[command(subcommand)]
        cmd: RecipeCommands,
    },
    /// Policy evaluation and validation
    Policy {
        #[command(subcommand)]
        cmd: PolicyCommands,
    },
    /// Audit log and verification
    Audit {
        #[command(subcommand)]
        cmd: AuditCommands,
    },
    /// Show daemon status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Show health and diagnostic checks
    #[command(alias = "health")]
    Doctor,
}

#[derive(Subcommand, Debug)]
enum AgentCommands {
    /// Enroll a new agent principal
    Enroll {
        #[arg(long)]
        name: String,
    },
    /// List enrolled agents
    List,
}

#[derive(Subcommand, Debug)]
enum CredentialCommands {
    /// Add a new credential to the OS keychain
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        r#type: CredentialType,
        #[arg(long)]
        origin: String,
    },
    /// Check if a credential exists in the keychain
    Check {
        #[arg(long)]
        name: String,
    },
    /// Delete a credential from the OS keychain
    Delete {
        #[arg(long)]
        name: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CredentialType {
    Password,
    Totp,
    SensitiveForm,
}

impl CredentialType {
    fn kind(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "totp",
            Self::SensitiveForm => "sensitive_form",
        }
    }

    fn action(self) -> ActionKind {
        match self {
            Self::Password => ActionKind::AuthenticatePassword,
            Self::Totp => ActionKind::AuthenticateTotp,
            Self::SensitiveForm => ActionKind::FormSensitiveFill,
        }
    }
}

#[derive(Subcommand, Debug)]
enum RecipeCommands {
    /// Validate a site recipe JSON file
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Validate a policy YAML/JSON file
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// Verify the integrity of the audit hash chain
    Verify,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let secretctl_dir = PathBuf::from(home).join(".secretctl");
    let run_dir = secretctl_dir.join("run");

    match cli.command {
        Commands::Init => {
            tokio::fs::create_dir_all(&run_dir).await?;
            let db_path = secretctl_dir.join("secretctl.db");
            let _store = SqliteStore::open(&db_path)?;

            let key_path = secretctl_dir.join("broker_key.pub");
            let provider = MacOsKeychainProvider::new();
            let keypair = if provider.exists("installation-signing-key").await? {
                let secret = provider.get_secret("installation-signing-key").await?;
                KeyPair::from_bytes(secret.as_bytes())?
            } else {
                let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng.fill_bytes(key_bytes.as_mut());
                provider
                    .store_secret("installation-signing-key", key_bytes.as_ref())
                    .await?;
                KeyPair::from_bytes(key_bytes.as_ref())?
            };
            tokio::fs::write(&key_path, keypair.public_key_bytes()).await?;

            println!("Initialized secretctl in {:?}", secretctl_dir);
            println!("SQLite store initialized at {:?}", db_path);
            println!("Broker public key available at {:?}", key_path);
        }
        Commands::Agent { cmd } => {
            let db_path = secretctl_dir.join("secretctl.db");
            let store = SqliteStore::open(&db_path)?;

            match cmd {
                AgentCommands::Enroll { name } => {
                    let agent_key = KeyPair::generate();
                    let agent = AgentPrincipal {
                        agent_id: AgentId::new(),
                        public_key: agent_key.public_key_bytes().to_vec(),
                        display_name: name.clone(),
                        executable_hash: None,
                        state: "enrolled".to_string(),
                        created_at: Utc::now(),
                    };
                    store.insert_agent(&agent)?;
                    println!(
                        "Successfully enrolled agent '{}' with ID: {}",
                        name, agent.agent_id
                    );
                }
                AgentCommands::List => {
                    println!("Listing enrolled agents (from {:?})", db_path);
                }
            }
        }
        Commands::Credential { cmd } => {
            let db_path = secretctl_dir.join("secretctl.db");
            let store = SqliteStore::open(&db_path)?;
            let provider = MacOsKeychainProvider::new();
            match cmd {
                CredentialCommands::Add {
                    name,
                    r#type,
                    origin,
                } => {
                    let origin = CanonicalOrigin::parse(&origin)?;
                    let credential_id = CredentialId::new();
                    let provider_locator = credential_id.to_string();
                    let secret_val = zeroize::Zeroizing::new(
                        tokio::task::spawn_blocking(|| {
                            rpassword::prompt_password("Secret value: ")
                        })
                        .await??,
                    );
                    provider
                        .store_secret(&provider_locator, secret_val.as_bytes())
                        .await?;
                    let descriptor = CredentialDescriptor {
                        credential_id,
                        name: name.clone(),
                        kind: r#type.kind().to_string(),
                        provider: provider.provider_name().to_string(),
                        provider_locator: provider_locator.clone(),
                        allowed_actions: vec![r#type.action()],
                        metadata_json: serde_json::json!({
                            "origin": origin.to_string(),
                        })
                        .to_string(),
                        disabled_at: None,
                    };
                    if let Err(error) = store.insert_credential(&descriptor) {
                        let _ = provider.delete_secret(&provider_locator).await;
                        return Err(error.into());
                    }
                    println!(
                        "Successfully stored credential '{}' in macOS Keychain",
                        name
                    );
                }
                CredentialCommands::Check { name } => {
                    let descriptor = store.get_credential_by_name(&name)?;
                    let exists = provider.exists(&descriptor.provider_locator).await?;
                    if exists {
                        println!("Credential '{}' exists in Keychain", name);
                    } else {
                        println!("Credential '{}' not found in Keychain", name);
                    }
                }
                CredentialCommands::Delete { name } => {
                    let descriptor = store.get_credential_by_name(&name)?;
                    provider.delete_secret(&descriptor.provider_locator).await?;
                    store.delete_credential_by_name(&name)?;
                    println!("Successfully deleted credential '{}' from Keychain", name);
                }
            }
        }
        Commands::Recipe { cmd } => match cmd {
            RecipeCommands::Validate { path } => {
                let content = tokio::fs::read_to_string(&path).await?;
                let _recipe_json: serde_json::Value = serde_json::from_str(&content)?;
                println!("Recipe {:?} is valid JSON.", path);
            }
        },
        Commands::Policy { cmd } => match cmd {
            PolicyCommands::Validate { path } => {
                let content = tokio::fs::read_to_string(&path).await?;
                let doc = if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    PolicyDocument::from_json(&content)?
                } else {
                    PolicyDocument::from_yaml(&content)?
                };
                println!(
                    "Policy {:?} is valid (version {}, {} rules).",
                    path,
                    doc.version,
                    doc.rules.len()
                );
            }
        },
        Commands::Audit { cmd } => match cmd {
            AuditCommands::Verify => {
                let db_path = secretctl_dir.join("secretctl.db");
                if !db_path.exists() {
                    anyhow::bail!("No audit database found at {:?}", db_path);
                } else {
                    let store = SqliteStore::open(&db_path)?;
                    let events = store.list_audit_events()?;
                    verify_audit_chain(&events)?;
                    println!("Audit chain verified successfully.");
                }
            }
        },
        Commands::Status { json } => {
            let socket_path = secretctl_dir.join("run/admin.sock");
            let running = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::net::UnixStream::connect(&socket_path),
            )
            .await
            .is_ok_and(|result| result.is_ok());
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": if running { "running" } else { "unavailable" },
                        "admin_socket": socket_path,
                    })
                );
            } else if running {
                println!("secretctl daemon is running");
            } else {
                anyhow::bail!("secretctl daemon is unavailable");
            }
        }
        Commands::Doctor => {
            let db_path = secretctl_dir.join("secretctl.db");
            anyhow::ensure!(
                db_path.exists(),
                "metadata database is missing; run `secretctl init`"
            );
            let store = SqliteStore::open(&db_path)?;
            verify_audit_chain(&store.list_audit_events()?)?;
            let provider = MacOsKeychainProvider::new();
            anyhow::ensure!(
                provider.exists("installation-signing-key").await?,
                "installation signing key is unavailable"
            );
            println!("database: ok");
            println!("audit chain: ok");
            println!("macOS keychain: ok");
            let admin_socket = secretctl_dir.join("run/admin.sock");
            println!(
                "daemon: {}",
                if admin_socket.exists() {
                    "socket present"
                } else {
                    "not running"
                }
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_add_never_accepts_secret_on_command_line() {
        let parsed = Cli::try_parse_from([
            "secretctl",
            "credential",
            "add",
            "--name",
            "github-work",
            "--type",
            "password",
            "--origin",
            "https://github.com",
            "--value",
            "must-not-be-accepted",
        ]);
        assert!(parsed.is_err());
    }
}
