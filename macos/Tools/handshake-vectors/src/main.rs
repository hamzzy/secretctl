//! Emits cross-language test vectors for the Swift admin client.
//!
//! The Swift app reimplements the broker handshake with CryptoKit rather than
//! linking the Rust crates, so the two implementations can drift silently. They
//! cannot drift *quietly*: every primitive on the path from `session.hello` to
//! an encrypted RPC frame is pinned here from the real Rust code, and
//! `SecretctlKitTests` asserts the Swift side reproduces it byte for byte.
//!
//! Run `just -f macos/justfile vectors` (or `cargo run` here) after any change
//! to `secretctl-crypto` or the handshake transcript.

use secretctl_crypto::{KeyPair, SecureChannel, compute_context_digest};
use secretctl_protocol::{
    ReasonSource, SessionHelloParams, UiActiveOperation, UiActivityEvent, UiAgent,
    UiAuthorizationRequest, UiBrowserSession, UiCredential, UiEventOutcome, UiFlowStep, UiGrant,
    UiOperationStep, UiProtectionState, UiStatus, UiStepState, session_auth_transcript,
};
use secretctl_domain::{ActionKind, RiskLevel};

fn main() {
    let mut vectors = serde_json::Map::new();

    // 1. Length-prefixed transcript hashing.
    vectors.insert(
        "context_digest".to_string(),
        serde_json::json!({
            "components": ["secretctl-session-hello-v1", "alpha", "", "beta"],
            "digest_hex": hex::encode(compute_context_digest(&[
                b"secretctl-session-hello-v1",
                b"alpha",
                b"",
                b"beta",
            ])),
        }),
    );

    // 2. The exact transcript the admin socket signs.
    let hello = SessionHelloParams {
        protocol_version: "1.0".to_string(),
        role: "admin".to_string(),
        principal_id: "local-admin".to_string(),
        client_nonce: "Y2xpZW50LW5vbmNlLWZpeGVkLTAwMDA".to_string(),
        supported_suites: vec!["X25519-HKDF-SHA256-CHACHA20POLY1305".to_string()],
    };
    let server_nonce = "3f1d9c22-0000-4000-8000-000000000001";
    let server_public = [7u8; 32];
    let client_public = [9u8; 32];
    vectors.insert(
        "session_auth_transcript".to_string(),
        serde_json::json!({
            "protocol_version": hello.protocol_version,
            "role": hello.role,
            "principal_id": hello.principal_id,
            "client_nonce": hello.client_nonce,
            "server_nonce": server_nonce,
            "server_ephemeral_public_hex": hex::encode(server_public),
            "client_ephemeral_public_hex": hex::encode(client_public),
            "digest_hex": hex::encode(session_auth_transcript(
                &hello, server_nonce, &server_public, &client_public,
            )),
        }),
    );

    // 3. Ed25519 over a fixed seed, matching how the Keychain seed is used.
    let seed = [0x42u8; 32];
    let keypair = KeyPair::from_bytes(&seed).expect("32-byte seed");
    let message = b"secretctl admin handshake vector";
    vectors.insert(
        "ed25519".to_string(),
        serde_json::json!({
            "seed_hex": hex::encode(seed),
            "public_key_hex": hex::encode(keypair.public_key_bytes()),
            "message_utf8": String::from_utf8_lossy(message),
            "signature_hex": hex::encode(keypair.sign(message)),
        }),
    );

    // 4. The channel itself. Deterministic because the nonce is a counter, so
    //    the Swift client must produce these exact frames and read the
    //    daemon's back.
    let shared_secret = [0x5au8; 32];
    let salt = server_nonce.as_bytes();
    let info = b"secretctl-admin-session-v1";

    let mut client = SecureChannel::new_client(&shared_secret, salt, info);
    let client_frames: Vec<String> = ["first from client", "second from client"]
        .iter()
        .map(|plaintext| hex::encode(client.encrypt(plaintext.as_bytes()).unwrap()))
        .collect();

    let mut server = SecureChannel::new_server(&shared_secret, salt, info);
    let server_frames: Vec<serde_json::Value> = ["first from daemon", "second from daemon"]
        .iter()
        .map(|plaintext| {
            serde_json::json!({
                "plaintext_utf8": plaintext,
                "frame_hex": hex::encode(server.encrypt(plaintext.as_bytes()).unwrap()),
            })
        })
        .collect();

    vectors.insert(
        "secure_channel".to_string(),
        serde_json::json!({
            "shared_secret_hex": hex::encode(shared_secret),
            "salt_utf8": server_nonce,
            "info_utf8": "secretctl-admin-session-v1",
            "client_to_server": [
                {"plaintext_utf8": "first from client", "frame_hex": client_frames[0]},
                {"plaintext_utf8": "second from client", "frame_hex": client_frames[1]},
            ],
            "server_to_client": server_frames,
        }),
    );

    // 5. Serialized UI DTOs, so the Swift `Codable` models are checked against
    //    the daemon's real field names rather than against a hand-copy of them.
    //    A renamed field would otherwise fail silently at runtime, leaving the
    //    popover blank with no build error anywhere.
    let timestamp = "2026-08-24T04:00:00Z".parse::<chrono::DateTime<chrono::Utc>>().unwrap();

    let request = UiAuthorizationRequest {
        approval_id: "apr_01".to_string(),
        request_id: "req_01".to_string(),
        agent_name: "Claude".to_string(),
        agent_id: "agt_01".to_string(),
        credential_name: "github-work".to_string(),
        provider: "macOS Keychain".to_string(),
        origin: "https://github.com:443".to_string(),
        action: ActionKind::AuthenticatePassword,
        action_label: "Sign in".to_string(),
        flow_steps: vec![
            UiFlowStep { role: "password".to_string(), label: "Password".to_string(), optional: false },
            UiFlowStep { role: "totp".to_string(), label: "TOTP".to_string(), optional: true },
        ],
        risk: RiskLevel::Medium,
        reason: Some("Review open pull requests".to_string()),
        reason_source: ReasonSource::AgentProvided,
        context_digest: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string(),
        expires_at: timestamp,
        requires_presence: true,
        is_first_for_agent: true,
        grantable: true,
    };

    let status = UiStatus {
        protection: UiProtectionState::SensitiveOperation,
        pending_approvals: 1,
        active_operation: Some(UiActiveOperation {
            request_id: "req_01".to_string(),
            agent_name: "Claude".to_string(),
            credential_name: "github-work".to_string(),
            origin: "https://github.com:443".to_string(),
            action_label: "Sign in".to_string(),
            steps: vec![
                UiOperationStep { label: "Authorization".to_string(), state: UiStepState::Done },
                UiOperationStep { label: "Password".to_string(), state: UiStepState::Done },
                UiOperationStep { label: "TOTP".to_string(), state: UiStepState::Active },
            ],
            confirmed_protections: vec![
                "Screenshot capture blocked".to_string(),
                "DOM extraction blocked".to_string(),
            ],
            protection_verified: true,
        }),
        browser_sessions_connected: 1,
        agents_enrolled: 2,
        agents_active: 1,
        active_grants: 3,
        providers: vec!["macOS Keychain".to_string()],
        policy_fingerprint: "sha256:abcd1234".to_string(),
        audit_chain_intact: true,
    };

    let grant = UiGrant {
        grant_id: "gnt_01".to_string(),
        agent_name: "Claude".to_string(),
        credential_name: "github-work".to_string(),
        origin: "https://github.com:443".to_string(),
        action: ActionKind::AuthenticateTotp,
        action_label: "Complete TOTP".to_string(),
        risk_ceiling: RiskLevel::Medium,
        require_presence: true,
        created_at: timestamp,
        expires_at: timestamp,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: Some(timestamp),
        use_count: 4,
        active: true,
    };

    let agent = UiAgent {
        agent_id: "agt_01".to_string(),
        display_name: "Claude".to_string(),
        role: "agent".to_string(),
        state: "enrolled".to_string(),
        created_at: timestamp,
        active_grants: 3,
        recent_event_count: 12,
        last_activity_at: Some(timestamp),
    };

    let credential = UiCredential {
        name: "github-work".to_string(),
        kind: "password".to_string(),
        provider: "macOS Keychain".to_string(),
        allowed_actions: vec![ActionKind::AuthenticatePassword, ActionKind::AuthenticateTotp],
        approved_origins: vec!["https://github.com:443".to_string()],
        used_by: vec!["Claude".to_string()],
        last_used_at: Some(timestamp),
        disabled: false,
    };

    let session = UiBrowserSession {
        session_id: "bsn_01".to_string(),
        profile: "Development".to_string(),
        state: "active".to_string(),
        assurance: "managed".to_string(),
        last_heartbeat_at: timestamp,
        active_tab_count: 2,
        current_origins: vec!["https://github.com:443".to_string()],
    };

    let event = UiActivityEvent {
        sequence: 42,
        event_id: "evt_01".to_string(),
        event_type: "execution.completed".to_string(),
        summary: "GitHub authentication".to_string(),
        outcome: UiEventOutcome::Success,
        actor_type: "broker".to_string(),
        actor_name: Some("Claude".to_string()),
        origin: Some("https://github.com:443".to_string()),
        action: Some(ActionKind::AuthenticatePassword),
        risk: Some(RiskLevel::Medium),
        error_code: None,
        created_at: timestamp,
    };

    vectors.insert(
        "dtos".to_string(),
        serde_json::json!({
            "authorization_request": request,
            "status": status,
            "grant": grant,
            "agent": agent,
            "credential": credential,
            "browser_session": session,
            "activity_event": event,
        }),
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Object(vectors)).unwrap()
    );
}
