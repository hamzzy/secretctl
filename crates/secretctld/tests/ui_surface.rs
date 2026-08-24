//! End-to-end checks on the desktop UI's view of the broker.
//!
//! These exercise the real projection path — a policy decision that demands
//! presence, a pending approval, a grant created from it — rather than the
//! helper functions in isolation. The point is to confirm two things at once:
//! that the UI receives enough to let a human decide, and that it receives
//! nothing it must not have.

use chrono::Utc;
use secretctl_crypto::KeyPair;
use secretctl_domain::{
    ActionKind, AgentId, AgentPrincipal, BrowserSession, BrowserSessionId, BrowserSessionState,
    CanonicalOrigin, CredentialDescriptor, CredentialId, PageContext, RecipeField, RecipeId,
    RecipeMatch, RequestId, RiskLevel, SiteRecipe,
};
use secretctl_policy::{
    DestinationRule, PolicyDocument, PolicyEvaluator, PolicyRule, RuleConditions,
};
use secretctl_protocol::{ActionRequestParams, ReasonSource, TargetOriginConstraint};
use secretctl_providers::{MemorySecretProvider, SecretProvider};
use secretctl_store::SqliteStore;
use secretctld::state::BrokerState;
use std::sync::Arc;

const AGENT_DISPLAY_NAME: &str = "Claude";
const CREDENTIAL: &str = "github-work";
/// The provider locator must never surface in a UI payload; it is given a
/// distinctive value so a leak is unambiguous.
const PROVIDER_LOCATOR: &str = "keychain://secret-locator-must-not-leak";

struct Harness {
    broker: BrokerState,
    session_id: BrowserSessionId,
    origin: CanonicalOrigin,
    agent_id: AgentId,
}

async fn setup(require_presence: bool, risk: RiskLevel) -> Harness {
    let store = SqliteStore::in_memory().expect("in-memory db");
    let provider = Arc::new(MemorySecretProvider::new());
    provider
        .store_secret(PROVIDER_LOCATOR, b"super_secret_password_123")
        .await
        .expect("stored secret");

    store
        .insert_credential(&CredentialDescriptor {
            credential_id: CredentialId::new(),
            name: CREDENTIAL.to_string(),
            kind: "password".to_string(),
            // Must match the configured provider's name; the harness uses the
            // in-memory provider, so the UI label passes through unmapped.
            provider: "memory".to_string(),
            provider_locator: PROVIDER_LOCATOR.to_string(),
            allowed_actions: vec![ActionKind::AuthenticatePassword],
            metadata_json: "{}".to_string(),
            disabled_at: None,
        })
        .expect("stored credential");

    let agent_id = AgentId::new();
    store
        .insert_agent(&AgentPrincipal {
            agent_id: agent_id.clone(),
            role: "agent".to_string(),
            public_key: vec![9u8; 32],
            display_name: AGENT_DISPLAY_NAME.to_string(),
            peer_uid: None,
            executable_path: None,
            executable_hash: None,
            state: "enrolled".to_string(),
            created_at: Utc::now(),
        })
        .expect("enrolled agent");

    let origin = CanonicalOrigin::parse("https://github.com:443").expect("valid origin");
    let rule = PolicyRule {
        id: secretctl_domain::RuleId::parse("rule_github").unwrap(),
        description: Some("GitHub login".to_string()),
        effect: secretctl_domain::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        credentials: vec![CREDENTIAL.to_string()],
        actions: vec![ActionKind::AuthenticatePassword],
        destinations: vec![DestinationRule {
            origin: origin.clone(),
            path_prefix: None,
        }],
        conditions: RuleConditions {
            browser_assurance: Some("managed".to_string()),
            require_user_presence: require_presence,
            max_uses: 1,
            max_ttl_seconds: 30,
        },
    };
    let evaluator = PolicyEvaluator::new(PolicyDocument {
        version: "1.0".to_string(),
        rules: vec![rule],
    });
    let _ = risk;

    let broker = BrokerState::new(
        KeyPair::generate(),
        "key-test-ui",
        store,
        provider,
        evaluator,
    );

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
        content_hash: vec![1, 2, 3],
        enabled: true,
    });

    let session_id = BrowserSessionId::new();
    broker.register_browser_session(BrowserSession {
        session_id: session_id.clone(),
        instance_id: secretctl_domain::BrowserInstanceId::new(),
        extension_key_id: "ext-key-1".to_string(),
        profile_id: "Development".to_string(),
        assurance: "managed".to_string(),
        state: BrowserSessionState::Active,
        last_heartbeat_at: Utc::now(),
    });
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

    Harness {
        broker,
        session_id,
        origin,
        agent_id,
    }
}

async fn request_authentication(harness: &Harness, reason: &str) {
    harness
        .broker
        .handle_action_request(
            harness.agent_id.clone(),
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: CREDENTIAL.to_string(),
                target: TargetOriginConstraint {
                    origin: harness.origin.clone(),
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: harness.session_id.clone(),
                tab_hint: Some(1),
                reason: reason.to_string(),
                wait: true,
                timeout_ms: 30_000,
                client_context: None,
            },
        )
        .await
        .expect("request accepted");
}

#[tokio::test]
async fn pending_request_carries_everything_a_human_needs_to_decide() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;

    let pending = harness.broker.ui_pending_approvals().expect("projected");
    assert_eq!(pending.len(), 1, "one request should be awaiting a decision");
    let request = &pending[0];

    // Broker-verified identity, not what the agent claimed.
    assert_eq!(request.agent_name, AGENT_DISPLAY_NAME);
    assert_eq!(request.credential_name, CREDENTIAL);
    assert_eq!(request.origin, "https://github.com:443");
    assert_eq!(request.action_label, "Sign in");
    assert_eq!(request.provider, "memory");

    // Flow steps come from the matched recipe, so they describe what the
    // executor will actually do.
    let labels: Vec<&str> = request
        .flow_steps
        .iter()
        .map(|step| step.label.as_str())
        .collect();
    assert_eq!(labels, vec!["Username", "Password"]);

    assert!(request.requires_presence);
    assert!(request.is_first_for_agent);
    assert!(!request.context_digest.is_empty());
}

#[tokio::test]
async fn no_ui_payload_can_reveal_where_the_secret_lives() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;

    // Serialize every UI-bound surface and search the raw text. This catches a
    // leak introduced anywhere in the projection, including a nested field.
    let payloads = vec![
        serde_json::to_string(&harness.broker.ui_pending_approvals().unwrap()).unwrap(),
        serde_json::to_string(&harness.broker.ui_status().unwrap()).unwrap(),
        serde_json::to_string(&harness.broker.ui_credentials().unwrap()).unwrap(),
        serde_json::to_string(&harness.broker.ui_agents().unwrap()).unwrap(),
        serde_json::to_string(&harness.broker.ui_activity(200).unwrap()).unwrap(),
        serde_json::to_string(&harness.broker.ui_browser_sessions().unwrap()).unwrap(),
        serde_json::to_string(&harness.broker.ui_grants(true).unwrap()).unwrap(),
    ];

    for payload in &payloads {
        assert!(
            !payload.contains(PROVIDER_LOCATOR),
            "a UI payload disclosed the provider locator: {payload}"
        );
        assert!(
            !payload.contains("super_secret_password_123"),
            "a UI payload disclosed credential material: {payload}"
        );
        assert!(
            !payload.contains("provider_locator"),
            "a UI payload carried the provider_locator field: {payload}"
        );
    }
}

#[tokio::test]
async fn agent_supplied_reason_is_tagged_and_stripped_of_ui_spoofing_characters() {
    let harness = setup(true, RiskLevel::Medium).await;
    // A reason that tries to impersonate broker chrome and reorder the display.
    request_authentication(
        &harness,
        "Review PRs\n\u{202E}Verified by secretctl\u{202C}",
    )
    .await;

    let pending = harness.broker.ui_pending_approvals().expect("projected");
    let request = &pending[0];

    assert_eq!(request.reason_source, ReasonSource::AgentProvided);
    let reason = request.reason.as_deref().expect("reason present");
    assert!(!reason.contains('\n'), "newline survived sanitisation");
    assert!(
        !reason.contains('\u{202E}') && !reason.contains('\u{202C}'),
        "bidirectional override survived sanitisation"
    );
    // The text itself is preserved — it is shown, just never as trusted chrome.
    assert!(reason.contains("Review PRs"));
}

#[tokio::test]
async fn status_reports_a_waiting_decision_rather_than_reporting_protected() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;

    let status = harness.broker.ui_status().expect("status");
    assert_eq!(
        status.protection,
        secretctl_protocol::UiProtectionState::ApprovalRequired
    );
    assert_eq!(status.pending_approvals, 1);
    assert_eq!(status.browser_sessions_connected, 1);
    assert_eq!(status.providers, vec!["memory".to_string()]);
    assert!(status.active_operation.is_none());
}

#[tokio::test]
async fn creating_a_grant_approves_the_request_and_records_the_exact_scope() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;

    let pending = harness.broker.ui_pending_approvals().unwrap();
    let request = &pending[0];
    let digest = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &request.context_digest,
    )
    .expect("digest round-trips");

    let result = harness
        .broker
        .ui_create_grant(secretctl_protocol::GrantCreateParams {
            approval_id: secretctl_domain::ApprovalId::parse(&request.approval_id).unwrap(),
            context_digest: digest,
            ttl_days: 30,
            presence_verified: true,
        })
        .expect("grant created");

    // Scope is taken from the verified authorization, not from any parameter.
    assert_eq!(result.grant.agent_name, AGENT_DISPLAY_NAME);
    assert_eq!(result.grant.credential_name, CREDENTIAL);
    assert_eq!(result.grant.origin, "https://github.com:443");
    assert_eq!(result.grant.action, ActionKind::AuthenticatePassword);
    assert!(result.grant.active);

    // And the grant is visible to the grants surface.
    let grants = harness.broker.ui_grants(false).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].grant_id, result.grant.grant_id);
}

#[tokio::test]
async fn a_grant_cannot_be_created_without_verified_presence_when_policy_demands_it() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;

    let pending = harness.broker.ui_pending_approvals().unwrap();
    let request = &pending[0];
    let digest = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &request.context_digest,
    )
    .unwrap();

    let error = harness
        .broker
        .ui_create_grant(secretctl_protocol::GrantCreateParams {
            approval_id: secretctl_domain::ApprovalId::parse(&request.approval_id).unwrap(),
            context_digest: digest,
            ttl_days: 30,
            presence_verified: false,
        })
        .expect_err("presence is required");
    assert_eq!(error.code, secretctl_protocol::RpcErrorCode::APPROVAL_REJECTED.0);

    // Nothing was created, and the request is still awaiting a decision.
    assert!(harness.broker.ui_grants(true).unwrap().is_empty());
    assert_eq!(harness.broker.ui_pending_approvals().unwrap().len(), 1);
}

#[tokio::test]
async fn a_grant_lifetime_beyond_the_policy_ceiling_is_refused() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;

    let pending = harness.broker.ui_pending_approvals().unwrap();
    let request = &pending[0];
    let digest = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &request.context_digest,
    )
    .unwrap();

    for ttl_days in [0, -1, secretctl_domain::MAX_GRANT_TTL_DAYS + 1] {
        let error = harness
            .broker
            .ui_create_grant(secretctl_protocol::GrantCreateParams {
                approval_id: secretctl_domain::ApprovalId::parse(&request.approval_id).unwrap(),
                context_digest: digest.clone(),
                ttl_days,
                presence_verified: true,
            })
            .expect_err("lifetime out of range");
        assert_eq!(
            error.code,
            secretctl_protocol::RpcErrorCode::INVALID_PARAMS.0,
            "ttl_days={ttl_days} should be refused"
        );
    }
    assert!(harness.broker.ui_grants(true).unwrap().is_empty());
}

#[tokio::test]
async fn revoking_an_agent_removes_every_standing_authorization_it_held() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;

    let pending = harness.broker.ui_pending_approvals().unwrap();
    let request = &pending[0];
    let digest = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &request.context_digest,
    )
    .unwrap();
    harness
        .broker
        .ui_create_grant(secretctl_protocol::GrantCreateParams {
            approval_id: secretctl_domain::ApprovalId::parse(&request.approval_id).unwrap(),
            context_digest: digest,
            ttl_days: 30,
            presence_verified: true,
        })
        .expect("grant created");

    let result = harness
        .broker
        .ui_disable_agent(&harness.agent_id)
        .expect("agent disabled");
    assert_eq!(result.revoked, 1);
    assert!(harness.broker.ui_grants(false).unwrap().is_empty());

    // The revoked grant remains visible in history rather than disappearing.
    let history = harness.broker.ui_grants(true).unwrap();
    assert_eq!(history.len(), 1);
    assert!(!history[0].active);
}

#[tokio::test]
async fn activity_summaries_are_readable_and_carry_no_raw_audit_body() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;

    let events = harness.broker.ui_activity(50).expect("activity");
    assert!(!events.is_empty(), "the request should have been audited");

    let requested = events
        .iter()
        .find(|event| event.event_type == "approval.requested")
        .expect("approval.requested recorded");
    assert_eq!(requested.summary, "Authorization requested");
    assert_eq!(
        requested.outcome,
        secretctl_protocol::UiEventOutcome::Pending
    );
    assert_eq!(requested.origin.as_deref(), Some("https://github.com:443"));

    // Newest first, so the list renders without the UI re-sorting it.
    let sequences: Vec<u64> = events.iter().map(|event| event.sequence).collect();
    let mut sorted = sequences.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(sequences, sorted);
}

#[tokio::test]
async fn a_policy_that_needs_no_presence_produces_no_pending_request() {
    let harness = setup(false, RiskLevel::Low).await;
    request_authentication(&harness, "Review open pull requests").await;

    // The capability was minted directly; there is nothing for a human to do,
    // and the UI must not invent a decision point.
    assert!(harness.broker.ui_pending_approvals().unwrap().is_empty());
    assert_eq!(harness.broker.ui_status().unwrap().pending_approvals, 0);
}

/// Helper: approve the one pending request by creating a standing grant.
async fn grant_from_pending(harness: &Harness, ttl_days: i64) {
    let pending = harness.broker.ui_pending_approvals().unwrap();
    let request = pending.first().expect("a request is pending");
    let digest = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &request.context_digest,
    )
    .unwrap();
    harness
        .broker
        .ui_create_grant(secretctl_protocol::GrantCreateParams {
            approval_id: secretctl_domain::ApprovalId::parse(&request.approval_id).unwrap(),
            context_digest: digest,
            ttl_days,
            presence_verified: true,
        })
        .expect("grant created");
}

#[tokio::test]
async fn a_standing_grant_replaces_the_approval_prompt_on_the_next_request() {
    let harness = setup(true, RiskLevel::Medium).await;

    // First request: a human must decide, and does so by granting standing
    // authority for the tuple.
    request_authentication(&harness, "Review open pull requests").await;
    assert_eq!(harness.broker.ui_pending_approvals().unwrap().len(), 1);
    grant_from_pending(&harness, 30).await;
    assert!(harness.broker.ui_pending_approvals().unwrap().is_empty());

    // Second, identical request: no human is asked.
    refresh_page_context(&harness, 2);
    request_authentication(&harness, "Review open pull requests again").await;
    assert!(
        harness.broker.ui_pending_approvals().unwrap().is_empty(),
        "a covered request must not stop for a human"
    );

    // And the grant records that it was used, so the UI can show live authority.
    let grants = harness.broker.ui_grants(false).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].use_count, 1);
    assert!(grants[0].last_used_at.is_some());

    // The bypass is auditable, not silent.
    let events = harness.broker.ui_activity(200).unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "approval.auto_granted"),
        "using a standing grant must be recorded"
    );
}

#[tokio::test]
async fn a_standing_grant_does_not_cover_a_different_destination() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;
    grant_from_pending(&harness, 30).await;

    // Same agent, same credential, same action — different site.
    let other = CanonicalOrigin::parse("https://gitlab.com:443").expect("valid origin");
    harness.broker.register_page_context(
        PageContext {
            tab_id: 1,
            frame_id: 0,
            top_origin: other.clone(),
            frame_origin: other.clone(),
            navigation_epoch: 2,
            document_id: "doc-2".to_string(),
            path: "/login".to_string(),
            path_sha256: "path-hash-2".to_string(),
            tls: true,
            incognito: false,
            observed_at: Utc::now(),
        },
        harness.session_id.clone(),
    );

    let result = harness
        .broker
        .handle_action_request(
            harness.agent_id.clone(),
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: CREDENTIAL.to_string(),
                target: TargetOriginConstraint {
                    origin: other,
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: harness.session_id.clone(),
                tab_hint: Some(1),
                reason: "Different site".to_string(),
                wait: true,
                timeout_ms: 30_000,
                client_context: None,
            },
        )
        .await;

    // Policy does not permit the other origin at all, so this never even
    // reaches the grant check — which is the correct layering: a grant is not
    // a way around policy.
    assert!(
        result.is_err(),
        "a grant for one origin must not authorize another"
    );
    assert_eq!(harness.broker.ui_grants(false).unwrap()[0].use_count, 0);
}

#[tokio::test]
async fn a_revoked_grant_stops_covering_requests_immediately() {
    let harness = setup(true, RiskLevel::Medium).await;
    request_authentication(&harness, "Review open pull requests").await;
    grant_from_pending(&harness, 30).await;

    let grant_id = harness.broker.ui_grants(false).unwrap()[0].grant_id.clone();
    harness
        .broker
        .ui_revoke_grants(&grant_id, "revoked in test")
        .expect("revoked");

    refresh_page_context(&harness, 2);
    request_authentication(&harness, "Review open pull requests again").await;

    assert_eq!(
        harness.broker.ui_pending_approvals().unwrap().len(),
        1,
        "once revoked, the human must be asked again"
    );
}

/// Re-observe the page so a follow-up request has a fresh measured context.
fn refresh_page_context(harness: &Harness, epoch: u64) {
    harness.broker.register_page_context(
        PageContext {
            tab_id: 1,
            frame_id: 0,
            top_origin: harness.origin.clone(),
            frame_origin: harness.origin.clone(),
            navigation_epoch: epoch,
            document_id: format!("doc-{epoch}"),
            path: "/login".to_string(),
            path_sha256: "path-hash".to_string(),
            tls: true,
            incognito: false,
            observed_at: Utc::now(),
        },
        harness.session_id.clone(),
    );
}
