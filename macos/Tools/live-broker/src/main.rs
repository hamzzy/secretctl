//! A throwaway `secretctld` with pending approvals already on it.
//!
//! The Swift client's decision path — echoing a context digest back on
//! `approval.decide`, taking an approval id into `grant.create` — cannot be
//! proven by unit tests: the digest round-trips through base64url, a JSON
//! array of bytes and `serde`'s `Vec<u8>`, and a mistake anywhere in that chain
//! fails only when a real broker checks it. So this stands up a real
//! `BrokerServer` on a real admin socket, in a temp installation directory,
//! with real pending approvals produced by the real policy path.
//!
//! It never touches the user's installation: the directory comes in on argv,
//! the store is a temp SQLite file, and the credential lives in the in-memory
//! provider. The broker identity is derived from a seed passed by the test, so
//! the Swift client can pin it without a Keychain dialog.
//!
//! Usage: `live-broker <installation-dir> <64-hex-char seed>`

use chrono::Utc;
use secretctl_crypto::KeyPair;
use secretctl_domain::{
    ActionKind, AgentId, AgentPrincipal, BrowserInstanceId, BrowserSession, BrowserSessionId,
    BrowserSessionState, CanonicalOrigin, CredentialDescriptor, CredentialId, PageContext,
    PolicyEffect, RecipeField, RecipeId, RecipeMatch, RequestId, RuleId, SiteRecipe,
};
use secretctl_policy::{
    DestinationRule, PolicyDocument, PolicyEvaluator, PolicyRule, RuleConditions,
};
use secretctl_protocol::{ActionRequestParams, TargetOriginConstraint};
use secretctl_providers::{MemorySecretProvider, SecretProvider};
use secretctl_store::SqliteStore;
use secretctld::{BrokerServer, BrokerState};
use std::sync::Arc;

const AGENT_NAME: &str = "Claude";
const CREDENTIAL: &str = "github-work";
/// Distinctive so a leak into any UI payload would be unmistakable.
const PROVIDER_LOCATOR: &str = "memory://secret-locator-must-not-leak";
const ORIGIN: &str = "https://github.com:443";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let directory = std::path::PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("usage: live-broker <dir> <seed-hex>"))?,
    );
    let seed_hex = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: live-broker <dir> <seed-hex>"))?;
    let seed = hex::decode(seed_hex)?;
    anyhow::ensure!(seed.len() == 32, "seed must be 32 bytes");
    let approval_count: usize = args.next().map(|n| n.parse()).transpose()?.unwrap_or(4);

    std::fs::create_dir_all(&directory)?;
    let runtime_dir = directory.join("run");

    // The client pins this file and requires it to equal the key it signs
    // with, exactly as it does against a real installation.
    let broker_key = KeyPair::from_bytes(&seed)?;
    std::fs::write(directory.join("broker_key.pub"), broker_key.public_key_bytes())?;

    let provider = Arc::new(MemorySecretProvider::new());
    provider
        .store_secret(PROVIDER_LOCATOR, b"super_secret_password_123")
        .await?;

    let store = SqliteStore::open(directory.join("secretctl.db"))?;
    store.insert_credential(&CredentialDescriptor {
        credential_id: CredentialId::new(),
        name: CREDENTIAL.to_string(),
        kind: "password".to_string(),
        provider: "memory".to_string(),
        provider_locator: PROVIDER_LOCATOR.to_string(),
        allowed_actions: vec![ActionKind::AuthenticatePassword],
        metadata_json: "{}".to_string(),
        disabled_at: None,
    })?;

    let agent_id = AgentId::new();
    store.insert_agent(&AgentPrincipal {
        agent_id: agent_id.clone(),
        role: "agent".to_string(),
        public_key: vec![9u8; 32],
        display_name: AGENT_NAME.to_string(),
        peer_uid: None,
        executable_path: None,
        executable_hash: None,
        state: "enrolled".to_string(),
        created_at: Utc::now(),
    })?;

    let origin = CanonicalOrigin::parse(ORIGIN).expect("valid origin");
    // Presence is required, because that is what routes a request to a human
    // instead of minting a capability outright. It also means the daemon must
    // refuse an approval that claims no presence — which is one of the things
    // the test asserts.
    let evaluator = PolicyEvaluator::new(PolicyDocument {
        version: "1.0".to_string(),
        rules: vec![PolicyRule {
            id: RuleId::parse("rule_github").unwrap(),
            description: Some("GitHub login".to_string()),
            effect: PolicyEffect::Allow,
            principals: vec!["*".to_string()],
            credentials: vec![CREDENTIAL.to_string()],
            actions: vec![ActionKind::AuthenticatePassword],
            destinations: vec![DestinationRule {
                origin: origin.clone(),
                path_prefix: None,
            }],
            conditions: RuleConditions {
                browser_assurance: Some("managed".to_string()),
                require_user_presence: true,
                max_uses: 1,
                max_ttl_seconds: 300,
            },
        }],
    });

    let broker = BrokerState::new(broker_key, "key-live-fixture", store, provider, evaluator);

    broker.register_recipe(SiteRecipe {
        recipe_id: RecipeId::parse("rcp_github_login").unwrap(),
        version: 1,
        name: "GitHub Login".to_string(),
        action: ActionKind::AuthenticatePassword,
        match_rule: RecipeMatch {
            top_origin: origin.clone(),
            path_prefix: Some("/login".to_string()),
            frame_origin: Some(origin.clone()),
        },
        fields: vec![
            RecipeField {
                role: "username".to_string(),
                selector: "input[name=login]".to_string(),
                optional: false,
                clear_first: true,
            },
            RecipeField {
                role: "password".to_string(),
                selector: "input[type=password]".to_string(),
                optional: false,
                clear_first: true,
            },
        ],
        submit: None,
        success_indicators: None,
        oauth: None,
        content_hash: vec![1, 2, 3],
        enabled: true,
    });

    let session_id = BrowserSessionId::new();
    broker.register_browser_session(BrowserSession {
        session_id: session_id.clone(),
        instance_id: BrowserInstanceId::new(),
        extension_key_id: "ext-key-1".to_string(),
        profile_id: "Development".to_string(),
        assurance: "managed".to_string(),
        state: BrowserSessionState::Active,
        last_heartbeat_at: Utc::now(),
    });
    // A decision is only valid while the measured page context is under two
    // seconds old, so the fixture heartbeats it the way the browser extension
    // would. Without this the approvals would go stale before the client could
    // act and every decide would come back "invalidated".
    let page_context = || PageContext {
        tab_id: 1,
        frame_id: 0,
        top_origin: origin.clone(),
        frame_origin: origin.clone(),
        navigation_epoch: 1,
        document_id: "doc-1".to_string(),
        path: "/login".to_string(),
        path_sha256: "path-hash".to_string(),
        tls: true,
        incognito: false,
        observed_at: Utc::now(),
    };
    broker.register_page_context(page_context(), session_id.clone());

    {
        let broker = broker.clone();
        let session_id = session_id.clone();
        let origin = origin.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(400));
            loop {
                ticker.tick().await;
                broker.register_page_context(
                    PageContext {
                        tab_id: 1,
                        frame_id: 0,
                        top_origin: origin.clone(),
                        frame_origin: origin.clone(),
                        navigation_epoch: 1,
                        document_id: "doc-1".to_string(),
                        path: "/login".to_string(),
                        path_sha256: "path-hash".to_string(),
                        tls: true,
                        incognito: false,
                        observed_at: Utc::now(),
                    },
                    session_id.clone(),
                );
            }
        });
    }

    // One pending approval per decision the test intends to make; each is
    // consumed by the decision that acts on it.
    for index in 0..approval_count {
        let reason = format!("Review open pull requests (request {})", index + 1);
        broker
            .handle_action_request(
                agent_id.clone(),
                ActionRequestParams {
                    request_id: RequestId::new(),
                    action: ActionKind::AuthenticatePassword,
                    identity: CREDENTIAL.to_string(),
                    target: TargetOriginConstraint {
                        origin: origin.clone(),
                        path_prefix: Some("/login".to_string()),
                    },
                    browser_session_id: session_id.clone(),
                    tab_hint: Some(1),
                    reason: reason.clone(),
                    // The fixture must not block on a human; the Swift side is
                    // the human here.
                    wait: false,
                    // The broker caps this at 60s, and it is also how long the
                    // approvals stay pending — ample for a test that runs in
                    // seconds, and it means a crashed run cleans up after
                    // itself rather than leaving live approvals behind.
                    timeout_ms: 60_000,
                    client_context: None,
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!("action request rejected: {}", error.message))?;
    }

    let pending = broker
        .ui_pending_approvals()
        .map_err(|error| anyhow::anyhow!("projection failed: {}", error.message))?;
    anyhow::ensure!(
        pending.len() == approval_count,
        "expected {} pending approvals, got {}",
        approval_count,
        pending.len()
    );

    BrokerServer::new(broker, &runtime_dir).start().await?;

    // The test reads this line to know the socket is up and which approvals to
    // act on.
    println!(
        "{}",
        serde_json::json!({
            "ready": true,
            "socket": runtime_dir.join("admin.sock"),
            "agent_name": AGENT_NAME,
            "credential": CREDENTIAL,
            "origin": ORIGIN,
            "approvals": pending.iter().map(|p| &p.approval_id).collect::<Vec<_>>(),
        })
    );
    use std::io::Write;
    std::io::stdout().flush()?;

    // Stay up until the test stops us. SIGTERM is what `Process.terminate()`
    // sends, so it is handled explicitly rather than left to the default
    // disposition — a fixture that ignores it turns a test teardown into a
    // hung run.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
    Ok(())
}
