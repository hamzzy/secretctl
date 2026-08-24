use chrono::{Duration, Utc};
use secretctl_audit::{create_audit_event, verify_audit_chain};
use secretctl_browser_gateway::cdp_filter::CdpFilter;
use secretctl_crypto::KeyPair;
use secretctl_domain::{
    ActionKind, AgentId, AgentPrincipal, BrowserInstanceId, BrowserSession, BrowserSessionId,
    BrowserSessionState, CanonicalOrigin, CredentialDescriptor, CredentialId, PageContext,
    RecipeField, RecipeId, RecipeMatch, RequestId, SiteRecipe,
};
use secretctl_policy::{
    DestinationRule, PolicyDocument, PolicyEvaluator, PolicyRule, RuleConditions,
};
use secretctl_protocol::{
    ActionRequestParams, ExecutorConsumeParams, ExecutorContextPayload, RpcErrorCode,
    TargetOriginConstraint,
};
use secretctl_providers::{MemorySecretProvider, SecretProvider};
use secretctl_store::SqliteStore;
use secretctld::state::BrokerState;
use std::collections::HashMap;
use std::sync::Arc;

async fn setup_adversarial_broker() -> (BrokerState, BrowserSessionId, CanonicalOrigin, AgentId) {
    let broker_key = KeyPair::generate();
    let store = SqliteStore::in_memory().expect("in-memory db");
    let provider = Arc::new(MemorySecretProvider::new());
    provider
        .store_secret("github-work", b"super_secret_password_123")
        .await
        .expect("stored secret");

    store
        .insert_credential(&CredentialDescriptor {
            credential_id: CredentialId::new(),
            name: "github-work".to_string(),
            kind: "password".to_string(),
            provider: "memory".to_string(),
            provider_locator: "github-work".to_string(),
            allowed_actions: vec![ActionKind::AuthenticatePassword],
            metadata_json: "{}".to_string(),
            disabled_at: None,
        })
        .expect("stored credential metadata");

    let agent_id = AgentId::new();
    let agent_key = KeyPair::generate();
    store
        .insert_agent(&AgentPrincipal {
            agent_id: agent_id.clone(),
            role: "agent".to_string(),
            public_key: agent_key.public_key_bytes().to_vec(),
            display_name: "test-agent".to_string(),
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
        description: Some("Allow github login".to_string()),
        effect: secretctl_domain::PolicyEffect::Allow,
        principals: vec![agent_id.to_string(), "*".to_string()],
        credentials: vec!["github-work".to_string()],
        actions: vec![ActionKind::AuthenticatePassword],
        destinations: vec![DestinationRule {
            origin: origin.clone(),
            path_prefix: None,
        }],
        conditions: RuleConditions {
            browser_assurance: Some("managed".to_string()),
            require_user_presence: false,
            max_uses: 1,
            max_ttl_seconds: 30,
        },
    };

    let policy_doc = PolicyDocument {
        version: "1.0".to_string(),
        rules: vec![rule],
    };
    let evaluator = PolicyEvaluator::new(policy_doc);

    let state = BrokerState::new(broker_key, "key-test-1", store, provider, evaluator);

    let recipe = SiteRecipe {
        recipe_id: RecipeId::parse("rcp_github_login").unwrap(),
        version: 1,
        name: "GitHub Login".to_string(),
        action: ActionKind::AuthenticatePassword,
        match_rule: RecipeMatch {
            top_origin: origin.clone(),
            path_prefix: Some("/login".to_string()),
            frame_origin: Some(origin.clone()),
        },
        fields: vec![RecipeField {
            role: "password".to_string(),
            selector: "input[type=password]".to_string(),
            optional: false,
            clear_first: true,
        }],
        submit: None,
        success_indicators: None,
        content_hash: vec![1, 2, 3],
        enabled: true,
    };
    state.register_recipe(recipe);

    let session_id = BrowserSessionId::new();
    let session = BrowserSession {
        session_id: session_id.clone(),
        instance_id: BrowserInstanceId::new(),
        extension_key_id: "ext-key-1".to_string(),
        profile_id: "default-profile".to_string(),
        assurance: "managed".to_string(),
        state: BrowserSessionState::Active,
        last_heartbeat_at: Utc::now(),
    };
    state.register_browser_session(session);
    state.register_page_context(
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

    (state, session_id, origin, agent_id)
}

#[tokio::test]
async fn test_attack_1_malicious_origin_spoofing_denied() {
    let (broker, session_id, _, agent_id) = setup_adversarial_broker().await;
    let evil_origin = CanonicalOrigin::parse("https://evil.example:443").unwrap();

    // Attacker tab navigated to evil.example
    broker.register_page_context(
        PageContext {
            tab_id: 2,
            frame_id: 0,
            top_origin: evil_origin.clone(),
            frame_origin: evil_origin.clone(),
            navigation_epoch: 1,
            document_id: "doc-evil".to_string(),
            path: "/login".to_string(),
            path_sha256: "evil-hash".to_string(),
            tls: true,
            incognito: false,
            observed_at: Utc::now(),
        },
        session_id.clone(),
    );

    // Agent attempts to request github-work credential on evil.example tab
    let result = broker
        .handle_action_request(
            agent_id,
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin: evil_origin,
                    path_prefix: None,
                },
                browser_session_id: session_id,
                tab_hint: Some(2),
                reason: "Phishing attempt".to_string(),
                wait: true,
                timeout_ms: 5000,
                client_context: None,
            },
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, RpcErrorCode::AUTH_POLICY_DENIED.0);
}

#[tokio::test]
async fn test_attack_2_navigation_epoch_tamper_fails_closed() {
    let (broker, session_id, origin, agent_id) = setup_adversarial_broker().await;

    broker
        .handle_action_request(
            agent_id,
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin: origin.clone(),
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: session_id.clone(),
                tab_hint: Some(1),
                reason: "Epoch race test".to_string(),
                wait: true,
                timeout_ms: 30000,
                client_context: None,
            },
        )
        .await
        .unwrap();

    let token = {
        let caps = broker.capabilities.lock().unwrap();
        caps.values().next().unwrap().token.clone()
    };

    // Navigation occurred during approval/injection: epoch is now 2
    let bad_context = ExecutorContextPayload {
        browser_session_id: session_id.clone(),
        tab_id: 1,
        frame_id: 0,
        document_id: "doc-1".to_string(),
        navigation_epoch: 2, // Tampered / changed epoch
        top_origin: origin.clone(),
        frame_origin: origin.clone(),
        path: "/login".to_string(),
        path_sha256: "path-hash".to_string(),
        tls: true,
        incognito: false,
    };

    let consume_res = broker
        .handle_executor_consume(ExecutorConsumeParams {
            capability_token: token,
            session_signature: "mock".to_string(),
            current_context: bad_context,
        })
        .await;

    assert!(consume_res.is_err());
    let err = consume_res.unwrap_err();
    assert_eq!(err.code, RpcErrorCode::EPOCH_INVALIDATED.0);
}

#[tokio::test]
async fn test_attack_3_capability_double_consume_and_replay_prevented() {
    let (broker, session_id, origin, agent_id) = setup_adversarial_broker().await;

    let page_context = ExecutorContextPayload {
        browser_session_id: session_id.clone(),
        tab_id: 1,
        frame_id: 0,
        document_id: "doc-1".to_string(),
        navigation_epoch: 1,
        top_origin: origin.clone(),
        frame_origin: origin.clone(),
        path: "/login".to_string(),
        path_sha256: "path-hash".to_string(),
        tls: true,
        incognito: false,
    };

    broker
        .handle_action_request(
            agent_id,
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin: origin.clone(),
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: session_id.clone(),
                tab_hint: Some(1),
                reason: "Replay race test".to_string(),
                wait: true,
                timeout_ms: 30000,
                client_context: None,
            },
        )
        .await
        .unwrap();

    let token = {
        let caps = broker.capabilities.lock().unwrap();
        caps.values().next().unwrap().token.clone()
    };

    // 20 concurrent tasks attempt to consume the single-use capability token
    let mut handles = Vec::new();
    for _ in 0..20 {
        let b = broker.clone();
        let t = token.clone();
        let ctx = page_context.clone();
        handles.push(tokio::spawn(async move {
            b.handle_executor_consume(ExecutorConsumeParams {
                capability_token: t,
                session_signature: "mock".to_string(),
                current_context: ctx,
            })
            .await
        }));
    }

    let mut successes = 0;
    let mut failures = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => successes += 1,
            Err(e) => {
                assert_eq!(e.code, RpcErrorCode::CAPABILITY_CONSUMED.0);
                failures += 1;
            }
        }
    }

    assert_eq!(successes, 1, "Exactly one consume attempt must succeed");
    assert_eq!(failures, 19, "All replay attempts must be rejected");
}

#[test]
fn test_attack_4_cdp_side_channel_denials_during_sensitive_window() {
    let filter = CdpFilter::new();
    let tab_id = 1;

    // Mark tab in sensitive window mode during secret injection
    filter.enter_sensitive_window(tab_id);

    // Attacker tries to capture screenshot during injection
    assert!(
        filter
            .validate_cdp_command("Page.captureScreenshot", Some(tab_id))
            .is_err()
    );

    // Attacker tries to dump accessibility tree
    assert!(
        filter
            .validate_cdp_command("Accessibility.getFullAXTree", Some(tab_id))
            .is_err()
    );

    // Attacker tries to dump DOM snapshot
    assert!(
        filter
            .validate_cdp_command("DOMSnapshot.captureSnapshot", Some(tab_id))
            .is_err()
    );

    // Attacker tries to extract cookies via CDP (globally prohibited)
    assert!(
        filter
            .validate_cdp_command("Network.getAllCookies", Some(tab_id))
            .is_err()
    );
}

#[tokio::test]
async fn test_attack_5_stale_heartbeat_revokes_active_capabilities() {
    let (broker, session_id, origin, agent_id) = setup_adversarial_broker().await;

    broker
        .handle_action_request(
            agent_id,
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin: origin.clone(),
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: session_id.clone(),
                tab_hint: Some(1),
                reason: "Stale heartbeat test".to_string(),
                wait: true,
                timeout_ms: 30000,
                client_context: None,
            },
        )
        .await
        .unwrap();

    let cap_id = {
        let caps = broker.capabilities.lock().unwrap();
        caps.keys().next().unwrap().clone()
    };

    // Fast forward 15 seconds without browser heartbeats
    let future_time = Utc::now() + Duration::seconds(15);
    let expired_count = broker.expire_stale_sessions(future_time).unwrap();
    assert_eq!(expired_count, 1);

    // Capability is now revoked
    let cap_state = broker
        .capabilities
        .lock()
        .unwrap()
        .get(&cap_id)
        .unwrap()
        .capability
        .state;
    assert_eq!(cap_state, secretctl_domain::CapabilityState::Revoked);
}

#[test]
fn test_attack_6_audit_hash_chain_tamper_detected() {
    let store = SqliteStore::in_memory().unwrap();
    let audit_key = vec![42u8; 32];
    let audit_keys = HashMap::from([(1, audit_key.clone())]);

    let event1 = create_audit_event(
        1,
        &secretctl_audit::GENESIS_PREVIOUS_HASH,
        1,
        &audit_key,
        "action.requested",
        "agent",
        Some("agent_1".to_string()),
        &secretctl_audit::AuditContext {
            request_id: Some("req_1".to_string()),
            credential_id: Some("github-work".to_string()),
            capability_id: None,
            browser_session_id: Some("bs_1".to_string()),
            target_origin: Some("https://github.com:443".to_string()),
            action: Some("authenticate.password".to_string()),
            decision: Some("allowed".to_string()),
            risk_level: Some("low".to_string()),
            error_code: None,
        },
        Utc::now(),
    )
    .unwrap();
    store.insert_audit_event(&event1).unwrap();

    let event2 = create_audit_event(
        2,
        &event1.event_hash,
        1,
        &audit_key,
        "capability.issued",
        "broker",
        None,
        &secretctl_audit::AuditContext {
            request_id: Some("req_1".to_string()),
            credential_id: Some("github-work".to_string()),
            capability_id: Some("cap_1".to_string()),
            browser_session_id: Some("bs_1".to_string()),
            target_origin: Some("https://github.com:443".to_string()),
            action: Some("authenticate.password".to_string()),
            decision: Some("issued".to_string()),
            risk_level: Some("low".to_string()),
            error_code: None,
        },
        Utc::now(),
    )
    .unwrap();
    store.insert_audit_event(&event2).unwrap();

    let events = store.list_audit_events().unwrap();
    assert!(verify_audit_chain(&events, &audit_keys).is_ok());

    // Attacker tampers with event hash
    let mut tampered = events.clone();
    tampered[1].previous_hash = vec![0u8; 32];
    assert!(verify_audit_chain(&tampered, &audit_keys).is_err());
}
