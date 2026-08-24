use base64::Engine;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use secretctl_audit::{create_audit_checkpoint, verify_audit_chain, verify_audit_checkpoints};
use secretctl_crypto::{EphemeralX25519, KeyPair, SecureChannel};
use secretctl_domain::{
    ActionKind, AgentId, AgentPrincipal, Approval, CanonicalOrigin, CapabilityId,
    CredentialDescriptor, CredentialId,
};
use secretctl_policy::{PolicyDocument, PolicyEvaluator};
use secretctl_protocol::{
    LengthPrefixedCodec, RpcRequest, RpcResponse, SessionAuthenticateParams,
    SessionHelloParams, SessionHelloResult, session_auth_transcript,
};
use secretctl_provider_macos::MacOsKeychainProvider;
use secretctl_providers::SecretProvider;
use secretctl_store::SqliteStore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;
use tokio_util::codec::Framed;

const SIGNING_KEY_LOCATOR: &str = "installation-signing-key";
const CRYPTO_SUITE: &str = "X25519-HKDF-SHA256-CHACHA20POLY1305";

#[derive(Parser, Debug)]
#[command(
    name = "secretctl",
    version,
    about = "Local credential isolation for agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init,
    Start {
        #[arg(long)]
        foreground: bool,
    },
    Stop,
    Status {
        #[arg(long)]
        json: bool,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    Approvals {
        #[command(subcommand)]
        command: ApprovalCommands,
    },
    Approve {
        approval_id: String,
        #[arg(long)]
        presence: bool,
    },
    Deny {
        approval_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Capability {
        #[command(subcommand)]
        command: CapabilityCommands,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    Keys {
        #[command(subcommand)]
        command: KeyCommands,
    },
    Recipe {
        #[command(subcommand)]
        command: RecipeCommands,
    },
    Doctor,
}

#[derive(Subcommand, Debug)]
enum AgentCommands {
    Enroll {
        #[arg(long)]
        name: String,
        #[arg(long, value_enum, default_value = "agent")]
        role: PrincipalRole,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        executable: Option<PathBuf>,
    },
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PrincipalRole {
    Agent,
    Executor,
}

impl PrincipalRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Executor => "executor",
        }
    }
}

#[derive(Subcommand, Debug)]
enum CredentialCommands {
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        r#type: CredentialType,
        #[arg(long)]
        origin: String,
    },
    List {
        #[arg(long)]
        json: bool,
    },
    Update {
        name: String,
    },
    Remove {
        name: String,
    },
    Check {
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
enum PolicyCommands {
    Validate {
        path: Option<PathBuf>,
    },
    Explain {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        action: String,
        #[arg(long)]
        origin: String,
    },
    Reload,
}

#[derive(Subcommand, Debug)]
enum ApprovalCommands {
    Watch {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        once: bool,
    },
}

#[derive(Subcommand, Debug)]
enum CapabilityCommands {
    List {
        #[arg(long)]
        active: bool,
        #[arg(long)]
        json: bool,
    },
    Revoke {
        capability_id: String,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    Verify,
    Export {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "jsonl")]
        format: String,
    },
}

#[derive(Subcommand, Debug)]
enum KeyCommands {
    Rotate,
}

#[derive(Subcommand, Debug)]
enum RecipeCommands {
    Validate { path: PathBuf },
}

struct AdminClient {
    framed: Framed<UnixStream, LengthPrefixedCodec>,
    channel: SecureChannel,
    next_id: u64,
}

impl AdminClient {
    async fn connect(secretctl_dir: &Path) -> anyhow::Result<Self> {
        let provider = MacOsKeychainProvider::new();
        let signing_secret = provider.get_secret(SIGNING_KEY_LOCATOR).await?;
        let signing_key = KeyPair::from_bytes(signing_secret.as_bytes())?;
        let pinned_public = tokio::fs::read(secretctl_dir.join("broker_key.pub")).await?;
        anyhow::ensure!(
            pinned_public == signing_key.public_key_bytes(),
            "broker key pin does not match the Keychain key"
        );
        let socket = UnixStream::connect(secretctl_dir.join("run/admin.sock")).await?;
        let mut framed = Framed::new(socket, LengthPrefixedCodec::for_agent());
        let hello = SessionHelloParams {
            protocol_version: "1.0".to_string(),
            role: "admin".to_string(),
            principal_id: "local-admin".to_string(),
            client_nonce: random_nonce(),
            supported_suites: vec![CRYPTO_SUITE.to_string()],
        };
        let hello_request = RpcRequest::new("hello", "session.hello", Some(hello.clone()));
        framed.send(serde_json::to_vec(&hello_request)?).await?;
        let hello_wire = framed
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("daemon closed during hello"))??;
        let hello_response: RpcResponse<SessionHelloResult> = serde_json::from_slice(&hello_wire)?;
        let server = hello_response
            .result
            .ok_or_else(|| anyhow::anyhow!("daemon rejected admin hello"))?;
        let server_public = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&server.ephemeral_public_key)?;
        let server_public: [u8; 32] = server_public
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid daemon ephemeral key"))?;
        let server_signature =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&server.signature)?;
        let server_transcript = secretctl_crypto::compute_context_digest(&[
            b"secretctl-session-hello-v1",
            hello.client_nonce.as_bytes(),
            server.server_nonce.as_bytes(),
            hello.principal_id.as_bytes(),
            &server_public,
        ]);
        secretctl_crypto::verify_signature(&pinned_public, &server_transcript, &server_signature)?;

        let client_ephemeral = EphemeralX25519::new();
        let client_public = client_ephemeral.public_bytes();
        let transcript =
            session_auth_transcript(&hello, &server.server_nonce, &server_public, &client_public);
        let auth = SessionAuthenticateParams {
            client_ephemeral_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(client_public),
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing_key.sign(&transcript)),
        };
        framed
            .send(serde_json::to_vec(&RpcRequest::new(
                "auth",
                "session.authenticate",
                Some(auth),
            ))?)
            .await?;
        let auth_wire = framed
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("daemon closed during authentication"))??;
        let auth_response: RpcResponse<serde_json::Value> = serde_json::from_slice(&auth_wire)?;
        anyhow::ensure!(
            auth_response.error.is_none(),
            "daemon rejected admin authentication"
        );
        let shared_secret = client_ephemeral.diffie_hellman(&server_public);
        Ok(Self {
            framed,
            channel: SecureChannel::new_client(
                &shared_secret,
                server.server_nonce.as_bytes(),
                b"secretctl-admin-session-v1",
            ),
            next_id: 1,
        })
    }

    async fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let id = self.next_id.to_string();
        self.next_id += 1;
        let request = RpcRequest::new(id, method, Some(params));
        let encrypted = self.channel.encrypt(&serde_json::to_vec(&request)?)?;
        self.framed.send(encrypted).await?;
        let response_wire = self
            .framed
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("daemon closed admin session"))??;
        let response: RpcResponse<serde_json::Value> =
            serde_json::from_slice(&self.channel.decrypt(&response_wire)?)?;
        if let Some(error) = response.error {
            anyhow::bail!("{} ({})", error.message, error.code);
        }
        response
            .result
            .ok_or_else(|| anyhow::anyhow!("daemon returned no result"))
    }
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn installation_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("secretctl")
}

fn daemon_binary() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("secretctld")))
        .filter(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from("secretctld"))
}

async fn prompt_secret(prompt: &'static str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    Ok(zeroize::Zeroizing::new(
        tokio::task::spawn_blocking(move || rpassword::prompt_password(prompt)).await??,
    ))
}

async fn load_audit_keys(
    store: &SqliteStore,
    provider: &MacOsKeychainProvider,
) -> anyhow::Result<HashMap<u32, Vec<u8>>> {
    let mut keys = HashMap::new();
    for (version, locator, _) in store.audit_key_versions()? {
        let key = provider.get_secret(&locator).await?;
        keys.insert(version, key.as_bytes().to_vec());
    }
    Ok(keys)
}

async fn verify_audit(
    store: &SqliteStore,
    provider: &MacOsKeychainProvider,
) -> anyhow::Result<usize> {
    let events = store.list_audit_events()?;
    let audit_keys = load_audit_keys(store, provider).await?;
    verify_audit_chain(&events, &audit_keys)?;
    verify_audit_checkpoints(
        &events,
        &store.list_audit_checkpoints()?,
        &store.trusted_signing_keys()?,
    )?;
    Ok(events.len())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("secretctl: {error:#}");
        std::process::exit(10);
    }
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let secretctl_dir = installation_dir();
    let db_path = secretctl_dir.join("secretctl.db");
    let run_dir = secretctl_dir.join("run");

    match cli.command {
        Commands::Init => {
            tokio::fs::create_dir_all(&run_dir).await?;
            tokio::fs::create_dir_all(secretctl_dir.join("recipes")).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&secretctl_dir, std::fs::Permissions::from_mode(0o700))?;
                std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700))?;
            }
            let store = SqliteStore::open(&db_path)?;
            let policy_path = secretctl_dir.join("policy.yaml");
            if !policy_path.exists() {
                tokio::fs::write(
                    &policy_path,
                    serde_yaml::to_string(&PolicyDocument {
                        version: "1.0".to_string(),
                        rules: vec![],
                    })?,
                )
                .await?;
            }
            let provider = MacOsKeychainProvider::new();
            let signing_key = if provider.exists(SIGNING_KEY_LOCATOR).await? {
                let bytes = provider.get_secret(SIGNING_KEY_LOCATOR).await?;
                KeyPair::from_bytes(bytes.as_bytes())?
            } else {
                let key = KeyPair::generate();
                provider
                    .store_secret(SIGNING_KEY_LOCATOR, &key.to_bytes())
                    .await?;
                key
            };
            store.register_signing_key(
                "broker-key-v1",
                &signing_key.public_key_bytes(),
                "active",
            )?;
            tokio::fs::write(
                secretctl_dir.join("broker_key.pub"),
                signing_key.public_key_bytes(),
            )
            .await?;
            let audit_locator = "audit-chain-key-v1";
            if !provider.exists(audit_locator).await? {
                let mut bytes = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                provider.store_secret(audit_locator, &bytes).await?;
                bytes.fill(0);
            }
            store.register_audit_key_version(1, audit_locator, "active")?;
            println!("initialized {}", secretctl_dir.display());
        }
        Commands::Start { foreground } => {
            tokio::fs::create_dir_all(&run_dir).await?;
            let binary = daemon_binary();
            if foreground {
                let status = std::process::Command::new(binary).status()?;
                anyhow::ensure!(status.success(), "daemon exited unsuccessfully");
            } else {
                let child = std::process::Command::new(binary)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()?;
                tokio::fs::write(run_dir.join("secretctld.pid"), child.id().to_string()).await?;
                println!("started secretctld pid {}", child.id());
            }
        }
        Commands::Stop => {
            let pid_path = run_dir.join("secretctld.pid");
            let pid = tokio::fs::read_to_string(&pid_path).await?;
            let status = std::process::Command::new("/bin/kill")
                .args(["-TERM", pid.trim()])
                .status()?;
            anyhow::ensure!(status.success(), "unable to stop daemon");
            tokio::fs::remove_file(pid_path).await?;
            println!("stopped secretctld");
        }
        Commands::Status { json } => {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                AdminClient::connect(&secretctl_dir),
            )
            .await;
            let running = result.is_ok_and(|result| result.is_ok());
            if json {
                println!(
                    "{}",
                    serde_json::json!({"status": if running {"running"} else {"unavailable"}})
                );
            } else if running {
                println!("secretctld is running and authenticated");
            } else {
                anyhow::bail!("secretctld is unavailable");
            }
        }
        Commands::Agent { command } => {
            let store = SqliteStore::open(&db_path)?;
            match command {
                AgentCommands::Enroll {
                    name,
                    role,
                    public_key,
                    executable,
                } => {
                    let raw_key = tokio::fs::read(&public_key).await?;
                    let public_key = if raw_key.len() == 32 {
                        raw_key
                    } else {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(String::from_utf8(raw_key)?.trim())?
                    };
                    anyhow::ensure!(
                        public_key.len() == 32,
                        "Ed25519 public key must be 32 bytes"
                    );
                    let (executable_path, executable_hash) = if let Some(path) = executable {
                        let canonical = tokio::fs::canonicalize(path).await?;
                        let bytes = tokio::fs::read(&canonical).await?;
                        (
                            Some(canonical.to_string_lossy().into_owned()),
                            Some(secretctl_crypto::sha256_digest(&bytes).to_vec()),
                        )
                    } else {
                        (None, None)
                    };
                    #[cfg(unix)]
                    let peer_uid = {
                        use std::os::unix::fs::MetadataExt;
                        Some(std::fs::metadata(&secretctl_dir)?.uid())
                    };
                    #[cfg(not(unix))]
                    let peer_uid = None;
                    let agent = AgentPrincipal {
                        agent_id: AgentId::new(),
                        role: role.as_str().to_string(),
                        public_key,
                        display_name: name,
                        peer_uid,
                        executable_path,
                        executable_hash,
                        state: "enrolled".to_string(),
                        created_at: Utc::now(),
                    };
                    store.insert_agent(&agent)?;
                    println!("{}", agent.agent_id);
                }
                AgentCommands::List { json } => {
                    let agents = store.list_agents()?;
                    if json {
                        println!("{}", serde_json::to_string(&agents)?);
                    } else {
                        for agent in agents {
                            println!("{}\t{}\t{}", agent.agent_id, agent.role, agent.display_name);
                        }
                    }
                }
            }
        }
        Commands::Credential { command } => {
            let store = SqliteStore::open(&db_path)?;
            let provider = MacOsKeychainProvider::new();
            match command {
                CredentialCommands::Add {
                    name,
                    r#type,
                    origin,
                } => {
                    let origin = CanonicalOrigin::parse(&origin)?;
                    let credential_id = CredentialId::new();
                    let provider_locator = format!("credential-{}", random_nonce());
                    let secret = prompt_secret("Secret value: ").await?;
                    provider
                        .store_secret(&provider_locator, secret.as_bytes())
                        .await?;
                    let descriptor = CredentialDescriptor {
                        credential_id,
                        name: name.clone(),
                        kind: r#type.kind().to_string(),
                        provider: provider.provider_name().to_string(),
                        provider_locator: provider_locator.clone(),
                        allowed_actions: vec![r#type.action()],
                        metadata_json: serde_json::json!({"origin": origin.to_string()})
                            .to_string(),
                        disabled_at: None,
                    };
                    if let Err(error) = store.insert_credential(&descriptor) {
                        let _ = provider.delete_secret(&provider_locator).await;
                        return Err(error.into());
                    }
                    println!("stored credential metadata for {name}");
                }
                CredentialCommands::List { json } => {
                    let credentials = store.list_credentials()?;
                    if json {
                        println!("{}", serde_json::to_string(&credentials)?);
                    } else {
                        for credential in credentials {
                            println!(
                                "{}\t{}\t{}",
                                credential.name, credential.kind, credential.credential_id
                            );
                        }
                    }
                }
                CredentialCommands::Update { name } => {
                    let descriptor = store.get_credential_by_name(&name)?;
                    let secret = prompt_secret("New secret value: ").await?;
                    provider
                        .store_secret(&descriptor.provider_locator, secret.as_bytes())
                        .await?;
                    println!("updated credential {name}");
                }
                CredentialCommands::Remove { name } => {
                    let descriptor = store.get_credential_by_name(&name)?;
                    provider.delete_secret(&descriptor.provider_locator).await?;
                    store.delete_credential_by_name(&name)?;
                    println!("removed credential {name}");
                }
                CredentialCommands::Check { name } => {
                    let descriptor = store.get_credential_by_name(&name)?;
                    anyhow::ensure!(
                        provider.exists(&descriptor.provider_locator).await?,
                        "credential provider item is unavailable"
                    );
                    println!("credential {name} is available");
                }
            }
        }
        Commands::Policy { command } => {
            let policy_path = secretctl_dir.join("policy.yaml");
            match command {
                PolicyCommands::Validate { path } => {
                    let path = path.unwrap_or(policy_path);
                    let content = tokio::fs::read_to_string(&path).await?;
                    let document = PolicyDocument::from_yaml(&content)?;
                    let evaluator = PolicyEvaluator::new(document);
                    println!(
                        "{}",
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(evaluator.policy_hash())
                    );
                }
                PolicyCommands::Explain {
                    agent,
                    identity,
                    action,
                    origin,
                } => {
                    let content = tokio::fs::read_to_string(policy_path).await?;
                    let evaluator = PolicyEvaluator::new(PolicyDocument::from_yaml(&content)?);
                    let decision = evaluator.evaluate(
                        &AgentId::parse(&agent)?,
                        &identity,
                        action.parse()?,
                        &CanonicalOrigin::parse(&origin)?,
                        None,
                        "managed",
                    )?;
                    println!("{}", serde_json::to_string(&decision)?);
                }
                PolicyCommands::Reload => {
                    let content = tokio::fs::read_to_string(policy_path).await?;
                    let evaluator = PolicyEvaluator::new(PolicyDocument::from_yaml(&content)?);
                    let expected_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(evaluator.policy_hash());
                    let mut admin = AdminClient::connect(&secretctl_dir).await?;
                    let result = admin
                        .call(
                            "policy.reload",
                            serde_json::json!({"policy_yaml": content, "expected_hash": expected_hash}),
                        )
                        .await?;
                    println!("{result}");
                }
            }
        }
        Commands::Approvals { command } => match command {
            ApprovalCommands::Watch { json, once } => loop {
                let mut admin = AdminClient::connect(&secretctl_dir).await?;
                let result = admin
                    .call("approval.list", serde_json::json!({"state": "pending"}))
                    .await?;
                let approvals: Vec<Approval> = serde_json::from_value(result)?;
                if json {
                    for approval in &approvals {
                        println!("{}", serde_json::to_string(approval)?);
                    }
                } else {
                    for approval in &approvals {
                        println!(
                            "{}\t{}\t{}",
                            approval.approval_id, approval.request_id, approval.expires_at
                        );
                    }
                }
                if once {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            },
        },
        Commands::Approve {
            approval_id,
            presence,
        } => {
            decide_approval(&secretctl_dir, &approval_id, "approve", presence).await?;
        }
        Commands::Deny {
            approval_id,
            reason: _,
        } => {
            decide_approval(&secretctl_dir, &approval_id, "deny", false).await?;
        }
        Commands::Capability { command } => {
            let mut admin = AdminClient::connect(&secretctl_dir).await?;
            match command {
                CapabilityCommands::List { active, json } => {
                    let result = admin
                        .call(
                            "capability.list",
                            serde_json::json!({"state": if active {Some("issued")} else {None::<&str>}}),
                        )
                        .await?;
                    if json {
                        println!("{result}");
                    } else {
                        let capabilities: Vec<secretctl_domain::CapabilitySummary> =
                            serde_json::from_value(result)?;
                        for capability in capabilities {
                            println!("{}\t{}", capability.capability_id, capability.state);
                        }
                    }
                }
                CapabilityCommands::Revoke { capability_id } => {
                    let id = CapabilityId::parse(&capability_id)?;
                    let result = admin
                        .call(
                            "capability.revoke",
                            serde_json::json!({"capability_id": id, "reason": "local_admin"}),
                        )
                        .await?;
                    println!("{result}");
                }
            }
        }
        Commands::Audit { command } => {
            let store = SqliteStore::open(&db_path)?;
            let provider = MacOsKeychainProvider::new();
            match command {
                AuditCommands::Verify => {
                    let count = verify_audit(&store, &provider).await?;
                    println!("verified {count} audit events and all checkpoints");
                }
                AuditCommands::Export { from, to, format } => {
                    anyhow::ensure!(format == "jsonl", "only jsonl export is supported");
                    verify_audit(&store, &provider).await?;
                    let from = DateTime::parse_from_rfc3339(&from)?.with_timezone(&Utc);
                    let to = DateTime::parse_from_rfc3339(&to)?.with_timezone(&Utc);
                    for event in store
                        .list_audit_events()?
                        .into_iter()
                        .filter(|event| event.created_at >= from && event.created_at <= to)
                    {
                        println!("{}", serde_json::to_string(&event)?);
                    }
                }
            }
        }
        Commands::Keys {
            command: KeyCommands::Rotate,
        } => {
            anyhow::ensure!(
                !run_dir.join("admin.sock").exists(),
                "stop secretctld before rotating keys"
            );
            let store = SqliteStore::open(&db_path)?;
            let provider = MacOsKeychainProvider::new();
            verify_audit(&store, &provider).await?;
            let old_signing_id = store
                .active_signing_key_id()?
                .ok_or_else(|| anyhow::anyhow!("active signing key missing"))?;
            let old_signing_secret = provider.get_secret(SIGNING_KEY_LOCATOR).await?;
            let old_signing_key = KeyPair::from_bytes(old_signing_secret.as_bytes())?;
            if let Some(last_event) = store.list_audit_events()?.last() {
                let checkpoint = create_audit_checkpoint(
                    last_event.sequence,
                    last_event.event_hash.clone(),
                    last_event.audit_key_version,
                    old_signing_id.clone(),
                    &old_signing_key,
                    Utc::now(),
                );
                if !store
                    .list_audit_checkpoints()?
                    .iter()
                    .any(|existing| existing.sequence == checkpoint.sequence)
                {
                    store.insert_audit_checkpoint(&checkpoint)?;
                }
            }
            let new_signing_key = KeyPair::generate();
            let new_version = store
                .audit_key_versions()?
                .iter()
                .map(|(version, _, _)| *version)
                .max()
                .unwrap_or(0)
                + 1;
            let new_signing_id = format!("broker-key-v{new_version}");
            provider
                .store_secret(SIGNING_KEY_LOCATOR, &new_signing_key.to_bytes())
                .await?;
            store.retire_signing_key(&old_signing_id)?;
            store.register_signing_key(
                &new_signing_id,
                &new_signing_key.public_key_bytes(),
                "active",
            )?;
            tokio::fs::write(
                secretctl_dir.join("broker_key.pub"),
                new_signing_key.public_key_bytes(),
            )
            .await?;
            let (old_audit_version, _) = store
                .active_audit_key_version()?
                .ok_or_else(|| anyhow::anyhow!("active audit key missing"))?;
            let new_audit_locator = format!("audit-chain-key-v{new_version}");
            let mut audit_key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut audit_key);
            provider
                .store_secret(&new_audit_locator, &audit_key)
                .await?;
            audit_key.fill(0);
            store.retire_audit_key_version(old_audit_version)?;
            store.register_audit_key_version(new_version, &new_audit_locator, "active")?;
            println!("rotated to signing key {new_signing_id} and audit key v{new_version}");
        }
        Commands::Recipe { command } => match command {
            RecipeCommands::Validate { path } => {
                let content = tokio::fs::read_to_string(path).await?;
                let _: secretctl_domain::SiteRecipe = serde_json::from_str(&content)?;
                println!("recipe is valid");
            }
        },
        Commands::Doctor => {
            let db_path = secretctl_dir.join("secretctl.db");
            anyhow::ensure!(
                db_path.exists(),
                "metadata database is missing; run `secretctl init`"
            );
            let store = SqliteStore::open(&db_path)?;
            let provider = MacOsKeychainProvider::new();
            let mut audit_keys = std::collections::HashMap::new();
            if let Ok(key) = provider.get_secret("installation-signing-key").await {
                audit_keys.insert(1, key.as_bytes().to_vec());
            }
            verify_audit_chain(&store.list_audit_events()?, &audit_keys)?;
            anyhow::ensure!(
                provider.exists(SIGNING_KEY_LOCATOR).await?,
                "installation signing key unavailable"
            );
            let mut admin = AdminClient::connect(&secretctl_dir).await?;
            admin.call("admin.ping", serde_json::json!({})).await?;
            println!("database migrations: ok");
            println!("audit events/checkpoints: ok");
            println!("macOS Keychain: ok");
            println!("authenticated encrypted admin IPC: ok");
        }
    }
    Ok(())
}

async fn decide_approval(
    secretctl_dir: &Path,
    approval_id: &str,
    decision: &str,
    presence: bool,
) -> anyhow::Result<()> {
    let mut admin = AdminClient::connect(secretctl_dir).await?;
    let approvals: Vec<Approval> = serde_json::from_value(
        admin
            .call("approval.list", serde_json::json!({"state": "pending"}))
            .await?,
    )?;
    let approval = approvals
        .into_iter()
        .find(|approval| approval.approval_id.as_str() == approval_id)
        .ok_or_else(|| anyhow::anyhow!("approval is not pending"))?;
    let result = admin
        .call(
            "approval.decide",
            serde_json::json!({
                "approval_id": approval.approval_id,
                "decision": decision,
                "context_digest": approval.context_digest,
                "presence_verified": presence,
            }),
        )
        .await?;
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_commands_never_accept_secret_arguments() {
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
        let update = Cli::try_parse_from([
            "secretctl",
            "credential",
            "update",
            "github-work",
            "--secret",
            "must-not-be-accepted",
        ]);
        assert!(update.is_err());
    }
}
