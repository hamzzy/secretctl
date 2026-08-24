use secretctl_crypto::KeyPair;
use secretctl_policy::{PolicyDocument, PolicyEvaluator};
use secretctl_provider_macos::MacOsKeychainProvider;
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

    println!("Starting secretctld daemon...");

    let home_dir = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let secretctl_dir = PathBuf::from(home_dir).join(".secretctl");
    tokio::fs::create_dir_all(&secretctl_dir).await?;

    let db_path = secretctl_dir.join("secretctl.db");
    let store = SqliteStore::open(&db_path)?;

    if !store.agent_exists("agent_default").unwrap_or(false) {
        let agent_key = KeyPair::generate();
        let default_agent = secretctl_domain::AgentPrincipal {
            agent_id: secretctl_domain::AgentId::new(),
            public_key: agent_key.public_key_bytes().to_vec(),
            display_name: "agent_default".to_string(),
            executable_hash: None,
            state: "enrolled".to_string(),
            created_at: chrono::Utc::now(),
        };
        let _ = store.insert_agent(&default_agent);
    }

    let provider = Arc::new(MacOsKeychainProvider::new());
    let broker_key = if provider
        .exists("installation-signing-key")
        .await
        .unwrap_or(false)
    {
        let secret = provider.get_secret("installation-signing-key").await?;
        KeyPair::from_bytes(secret.as_bytes())?
    } else {
        println!("No installation signing key found. Generating a new key in macOS Keychain...");
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
        rules: vec![secretctl_policy::PolicyRule {
            id: secretctl_domain::RuleId::parse("rule_default_dev").unwrap(),
            description: Some("Default local development policy".to_string()),
            effect: secretctl_domain::PolicyEffect::Allow,
            principals: vec!["*".to_string()],
            credentials: vec!["*".to_string()],
            actions: vec![
                secretctl_domain::ActionKind::AuthenticatePassword,
                secretctl_domain::ActionKind::AuthenticateTotp,
                secretctl_domain::ActionKind::FormSensitiveFill,
            ],
            destinations: vec![
                secretctl_policy::DestinationRule {
                    origin: secretctl_domain::CanonicalOrigin::parse("https://github.com:443")
                        .unwrap(),
                    path_prefix: None,
                },
                secretctl_policy::DestinationRule {
                    origin: secretctl_domain::CanonicalOrigin::parse("https://localhost:443")
                        .unwrap(),
                    path_prefix: None,
                },
            ],
            conditions: secretctl_policy::RuleConditions {
                browser_assurance: Some("managed".to_string()),
                require_user_presence: false,
                max_uses: 1,
                max_ttl_seconds: 60,
            },
        }],
    };
    let evaluator = PolicyEvaluator::new(default_policy);

    let state = BrokerState::new(broker_key, "broker-key-default", store, provider, evaluator);

    // Register default GitHub login and TOTP recipe
    let github_origin = secretctl_domain::CanonicalOrigin::parse("https://github.com:443").unwrap();
    state.register_recipe(secretctl_domain::SiteRecipe {
        recipe_id: secretctl_domain::RecipeId::parse("rcp_github_totp").unwrap(),
        version: 1,
        name: "GitHub TOTP".to_string(),
        action: secretctl_domain::ActionKind::AuthenticateTotp,
        top_origin: github_origin.clone(),
        path_prefix: None,
        frame_origin: Some(github_origin.clone()),
        fields: vec![secretctl_domain::RecipeField {
            role: "totp_code".to_string(),
            selector: "input[autocomplete='one-time-code'], input[name='otp'], input[type='tel']"
                .to_string(),
            optional: false,
            clear_first: true,
        }],
        submit: Some(secretctl_domain::RecipeSubmit {
            selector: Some("button[type='submit']".to_string()),
            auto_submit: true,
            delay_ms: None,
        }),
        success_indicators: None,
        content_hash: vec![],
        enabled: true,
    });
    state.register_recipe(secretctl_domain::SiteRecipe {
        recipe_id: secretctl_domain::RecipeId::parse("rcp_github_password").unwrap(),
        version: 1,
        name: "GitHub Password".to_string(),
        action: secretctl_domain::ActionKind::AuthenticatePassword,
        top_origin: github_origin.clone(),
        path_prefix: None,
        frame_origin: Some(github_origin),
        fields: vec![secretctl_domain::RecipeField {
            role: "password".to_string(),
            selector: "input[type='password']".to_string(),
            optional: false,
            clear_first: true,
        }],
        submit: Some(secretctl_domain::RecipeSubmit {
            selector: Some("button[type='submit']".to_string()),
            auto_submit: true,
            delay_ms: None,
        }),
        success_indicators: None,
        content_hash: vec![],
        enabled: true,
    });

    let runtime_dir = secretctl_dir.join("run");
    let server = BrokerServer::new(state, runtime_dir.clone());

    server.start().await?;

    println!("secretctld daemon started successfully.");
    println!("Listening on Unix domain sockets in: {:?}", runtime_dir);
    println!("  - agent:    {:?}", runtime_dir.join("agent.sock"));
    println!("  - executor: {:?}", runtime_dir.join("executor.sock"));
    println!("  - admin:    {:?}", runtime_dir.join("admin.sock"));
    println!("Press Ctrl+C to stop.\n");

    tokio::signal::ctrl_c().await?;
    println!("secretctld shutting down.");
    Ok(())
}
