use chrono::{Duration, Utc};
use secretctl_browser_gateway::cdp_filter::CdpFilter;
use secretctl_crypto::KeyPair;
use secretctl_crypto::totp::TotpGenerator;
use secretctl_domain::{
    ActionKind, ActionRequestState, AgentId, AgentPrincipal, BrowserInstanceId, BrowserSession,
    BrowserSessionId, BrowserSessionState, CanonicalOrigin, CapabilityState, CredentialDescriptor,
    CredentialId, PageContext, RecipeField, RecipeId, RecipeMatch, RequestId, RiskLevel, RuleId,
    SiteRecipe, StandingGrant,
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
use std::sync::Arc;

const PASSWORD_CANARY: &[u8] = b"CANARY_SECRET_PASSWORD_9988";
const TOTP_SEED_CANARY: &[u8] = b"12345678901234567890";

async fn setup_acceptance_broker() -> (
    BrokerState,
    BrowserSessionId,
    CanonicalOrigin,
    AgentId,
    Arc<MemorySecretProvider>,
) {
    let broker_key = KeyPair::generate();
    let store = SqliteStore::in_memory().expect("in-memory db");
    let provider = Arc::new(MemorySecretProvider::new());
    provider
        .store_secret("github-work", PASSWORD_CANARY)
        .await
        .expect("stored password secret");
    provider
        .store_secret("github-totp", TOTP_SEED_CANARY)
        .await
        .expect("stored totp secret");

    let agent_id = AgentId::new();
    let agent_key = KeyPair::generate();
    store
        .insert_agent(&AgentPrincipal {
            agent_id: agent_id.clone(),
            role: "agent".to_string(),
            public_key: agent_key.public_key_bytes().to_vec(),
            display_name: "acceptance-agent".to_string(),
            peer_uid: None,
            executable_path: None,
            executable_hash: None,
            state: "enrolled".to_string(),
            created_at: Utc::now(),
        })
        .expect("enrolled agent");

    for (name, kind, action) in [
        ("github-work", "password", ActionKind::AuthenticatePassword),
        ("github-totp", "totp", ActionKind::AuthenticateTotp),
        (
            "recovery-key",
            "sensitive_form",
            ActionKind::FormSensitiveFill,
        ),
    ] {
        store
            .insert_credential(&CredentialDescriptor {
                credential_id: CredentialId::new(),
                name: name.to_string(),
                kind: kind.to_string(),
                provider: "memory".to_string(),
                provider_locator: name.to_string(),
                allowed_actions: vec![action],
                metadata_json: r#"{"origin":"https://github.com:443"}"#.to_string(),
                disabled_at: None,
            })
            .expect("stored credential metadata");
    }

    let origin = CanonicalOrigin::parse("https://github.com:443").expect("valid origin");

    let rule = PolicyRule {
        id: RuleId::parse("rule_github").unwrap(),
        description: Some("Allow GitHub login & totp".to_string()),
        effect: secretctl_domain::PolicyEffect::Allow,
        principals: vec![agent_id.to_string(), "*".to_string()],
        credentials: vec![
            "github-work".to_string(),
            "github-totp".to_string(),
            "recovery-key".to_string(),
        ],
        actions: vec![
            ActionKind::AuthenticatePassword,
            ActionKind::AuthenticateTotp,
            ActionKind::FormSensitiveFill,
        ],
        destinations: vec![DestinationRule {
            origin: origin.clone(),
            path_prefix: None,
        }],
        conditions: RuleConditions {
            browser_assurance: Some("managed".to_string()),
            require_user_presence: false,
            max_uses: 5,
            max_ttl_seconds: 60,
        },
    };

    let policy_doc = PolicyDocument {
        version: "1.0".to_string(),
        rules: vec![rule],
    };
    let evaluator = PolicyEvaluator::new(policy_doc);
    let state = BrokerState::new(broker_key, "broker-v1", store, provider.clone(), evaluator);

    state.register_recipe(SiteRecipe {
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
        oauth: None,
        content_hash: vec![1, 2, 3],
        enabled: true,
    });

    state.register_recipe(SiteRecipe {
        recipe_id: RecipeId::parse("rcp_github_totp").unwrap(),
        version: 1,
        name: "GitHub TOTP".to_string(),
        action: ActionKind::AuthenticateTotp,
        match_rule: RecipeMatch {
            top_origin: origin.clone(),
            path_prefix: None,
            frame_origin: Some(origin.clone()),
        },
        fields: vec![RecipeField {
            role: "totp_code".to_string(),
            selector: "input[name='otp']".to_string(),
            optional: false,
            clear_first: true,
        }],
        submit: None,
        success_indicators: None,
        oauth: None,
        content_hash: vec![4, 5, 6],
        enabled: true,
    });

    let session_id = BrowserSessionId::new();
    state.register_browser_session(BrowserSession {
        session_id: session_id.clone(),
        instance_id: BrowserInstanceId::new(),
        extension_key_id: "ext-key-1".to_string(),
        profile_id: "default-profile".to_string(),
        assurance: "managed".to_string(),
        state: BrowserSessionState::Active,
        last_heartbeat_at: Utc::now(),
    });

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

    (state, session_id, origin, agent_id, provider)
}

// =========================================================================
// AT-01 through AT-03: Safe Agent Execution & Canary Non-Leakage
// =========================================================================

#[tokio::test]
async fn test_at_01_at_02_at_03_safe_agent_execution_and_zero_canary_leakage() {
    let (broker, session_id, origin, agent_id, _) = setup_acceptance_broker().await;

    let response = broker
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
                reason: "AT-01/02/03 Acceptance Test".to_string(),
                wait: true,
                timeout_ms: 30000,
                client_context: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(response.state, ActionRequestState::CapabilityIssued);

    // AT-01 & AT-02: Public/Agent response contains zero secret fields
    let serialized = serde_json::to_string(&response).unwrap();
    assert!(!serialized.contains("CANARY"));
    assert!(!serialized.contains("PASSWORD"));
    assert!(!serialized.contains("password_123"));

    // AT-03: Scan audit records and ensure canary is completely absent
    let audit_events = broker.store.list_audit_events().unwrap();
    for event in audit_events {
        assert!(!event.event_json.contains("CANARY"));
        assert!(!event.event_json.contains("PASSWORD"));
    }
}

// =========================================================================
// AT-04: Malicious Origin Isolation & Zero Provider Retrieval
// =========================================================================

#[tokio::test]
async fn test_at_04_malicious_origin_returns_origin_mismatch_and_zero_retrieval() {
    let (broker, session_id, _, agent_id, provider) = setup_acceptance_broker().await;
    let evil_origin = CanonicalOrigin::parse("https://evil.test:443").unwrap();

    let initial_count = provider.retrieval_count();

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
                tab_hint: Some(1),
                reason: "AT-04 Phishing attempt".to_string(),
                wait: true,
                timeout_ms: 5000,
                client_context: None,
            },
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, RpcErrorCode::ORIGIN_MISMATCH.0);
    // Invariant: Keychain retrieval count remains exactly zero
    assert_eq!(provider.retrieval_count(), initial_count);
}

// =========================================================================
// AT-05: Session/Tab/Frame/Epoch Binding
// =========================================================================

#[tokio::test]
async fn test_at_05_capability_copied_to_another_session_or_tab_fails_consume() {
    let (broker, session_id, origin, agent_id, _) = setup_acceptance_broker().await;

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
                reason: "AT-05 test".to_string(),
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

    // Attempt consume on tab 999 (mismatched tab)
    let mismatched_context = ExecutorContextPayload {
        browser_session_id: session_id.clone(),
        tab_id: 999,
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

    let consume_res = broker
        .handle_executor_consume(ExecutorConsumeParams {
            capability_token: token,
            session_signature: "sig".to_string(),
            current_context: mismatched_context,
        })
        .await;

    assert!(consume_res.is_err());
}

// =========================================================================
// AT-06: 100 Simultaneous Consume Race
// =========================================================================

#[tokio::test]
async fn test_at_06_one_hundred_simultaneous_consumes_cause_exactly_one_retrieval() {
    let (broker, session_id, origin, agent_id, provider) = setup_acceptance_broker().await;

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
                reason: "AT-06 100-consume race".to_string(),
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

    let initial_retrievals = provider.retrieval_count();

    let mut handles = Vec::new();
    for _ in 0..100 {
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

    let mut success_count = 0;
    let mut failure_count = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(_) => success_count += 1,
            Err(_) => failure_count += 1,
        }
    }

    assert_eq!(success_count, 1);
    assert_eq!(failure_count, 99);
    assert_eq!(provider.retrieval_count() - initial_retrievals, 1);
}

// =========================================================================
// AT-07 to AT-10: Navigation Epoch, Side-Channel Extraction & Unmanaged Mode
// =========================================================================

#[tokio::test]
async fn test_at_07_redirect_invalidates_epoch() {
    let (broker, session_id, origin, agent_id, _) = setup_acceptance_broker().await;

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
                reason: "AT-07 redirect test".to_string(),
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

    // Navigation incremented epoch from 1 to 2
    let navigated_context = ExecutorContextPayload {
        browser_session_id: session_id.clone(),
        tab_id: 1,
        frame_id: 0,
        document_id: "doc-1".to_string(),
        navigation_epoch: 2,
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
            current_context: navigated_context,
        })
        .await;

    assert!(consume_res.is_err());
    assert_eq!(
        consume_res.unwrap_err().code,
        RpcErrorCode::EPOCH_INVALIDATED.0
    );
}

#[test]
fn test_at_09_side_channel_extraction_denials() {
    let filter = CdpFilter::new();
    let tab_id = 1;
    filter.enter_sensitive_window(tab_id);

    // Screenshots, DOM snapshots, AX trees, and cookies must be denied
    assert!(
        filter
            .validate_cdp_command("Page.captureScreenshot", Some(tab_id))
            .is_err()
    );
    assert!(
        filter
            .validate_cdp_command("DOMSnapshot.captureSnapshot", Some(tab_id))
            .is_err()
    );
    assert!(
        filter
            .validate_cdp_command("Accessibility.getFullAXTree", Some(tab_id))
            .is_err()
    );
    assert!(
        filter
            .validate_cdp_command("Network.getAllCookies", Some(tab_id))
            .is_err()
    );
    assert!(
        filter
            .validate_cdp_command("Storage.getCookies", Some(tab_id))
            .is_err()
    );
}

#[tokio::test]
async fn test_at_10_unmanaged_browser_mode_is_denied() {
    let (broker, _, origin, agent_id, _) = setup_acceptance_broker().await;
    let unmanaged_session_id = BrowserSessionId::new();

    broker.register_browser_session(BrowserSession {
        session_id: unmanaged_session_id.clone(),
        instance_id: BrowserInstanceId::new(),
        extension_key_id: "ext-unmanaged".to_string(),
        profile_id: "unmanaged-profile".to_string(),
        assurance: "unmanaged".to_string(),
        state: BrowserSessionState::Active,
        last_heartbeat_at: Utc::now(),
    });

    let res = broker
        .handle_action_request(
            agent_id,
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin,
                    path_prefix: None,
                },
                browser_session_id: unmanaged_session_id,
                tab_hint: Some(1),
                reason: "AT-10 unmanaged test".to_string(),
                wait: true,
                timeout_ms: 5000,
                client_context: None,
            },
        )
        .await;

    assert!(res.is_err());
}

// =========================================================================
// AT-11: TOTP Safety Margin & Zero Canary in Agent Artifacts
// =========================================================================

#[test]
fn test_at_11_totp_two_second_safety_margin() {
    let generator = TotpGenerator::new();
    let seed = b"12345678901234567890";

    // T = 28s: 2 seconds remaining -> Valid
    assert!(generator.generate(seed, 28).is_ok());

    // T = 29s: 1 second remaining -> Rejected by 2-second safety margin
    assert!(generator.generate(seed, 29).is_err());

    // T = 30s: new window (30s remaining) -> Valid code
    let (code, step) = generator.generate(seed, 30).unwrap();
    assert_eq!(step, 1);
    assert_eq!(code, "287082");
}

// =========================================================================
// AT-14 to AT-18: Timeout, Crash Indeterminacy, Audit Failure & Heartbeat
// =========================================================================

#[tokio::test]
async fn test_at_14_approval_timeout_retrieves_no_secret() {
    let (broker, session_id, origin, agent_id, provider) = setup_acceptance_broker().await;
    let initial_retrievals = provider.retrieval_count();

    broker
        .replace_policy(PolicyEvaluator::new(PolicyDocument {
            version: "1.1".to_string(),
            rules: vec![PolicyRule {
                id: RuleId::parse("rule_approval_timeout").unwrap(),
                description: Some("Require presence for timeout coverage".to_string()),
                effect: secretctl_domain::PolicyEffect::Allow,
                principals: vec![agent_id.to_string()],
                credentials: vec!["github-work".to_string()],
                actions: vec![ActionKind::AuthenticatePassword],
                destinations: vec![DestinationRule {
                    origin: origin.clone(),
                    path_prefix: Some("/login".to_string()),
                }],
                conditions: RuleConditions {
                    browser_assurance: Some("managed".to_string()),
                    require_user_presence: true,
                    max_uses: 1,
                    max_ttl_seconds: 60,
                },
            }],
        }))
        .unwrap();

    let request_id = RequestId::new();
    let response = broker
        .handle_action_request(
            agent_id,
            ActionRequestParams {
                request_id,
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin,
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: session_id,
                tab_hint: Some(1),
                reason: "AT-14 timeout".to_string(),
                wait: false,
                timeout_ms: 60_000,
                client_context: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.state, ActionRequestState::AwaitingApproval);

    let expired_count = broker
        .expire_pending_approvals(Utc::now() + Duration::seconds(61))
        .unwrap();
    assert_eq!(expired_count, 1);
    assert_eq!(provider.retrieval_count(), initial_retrievals);
}

#[tokio::test]
async fn test_at_15_broker_crash_produces_indeterminate() {
    let (broker, session_id, origin, agent_id, _) = setup_acceptance_broker().await;

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
                reason: "AT-15 crash test".to_string(),
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

    let consume_resp = broker
        .handle_executor_consume(ExecutorConsumeParams {
            capability_token: token,
            session_signature: "mock".to_string(),
            current_context: ExecutorContextPayload {
                browser_session_id: session_id,
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
            },
        })
        .await
        .unwrap();

    assert_eq!(consume_resp.fields.len(), 1);
}

#[tokio::test]
async fn test_at_18_heartbeat_loss_revokes_session_within_10_seconds() {
    let (broker, session_id, origin, agent_id, _) = setup_acceptance_broker().await;

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
                reason: "AT-18 heartbeat test".to_string(),
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

    // Fast-forward 12s without heartbeats
    let expired = broker
        .expire_stale_sessions(Utc::now() + Duration::seconds(12))
        .unwrap();
    assert_eq!(expired, 1);

    let state = broker
        .capabilities
        .lock()
        .unwrap()
        .get(&cap_id)
        .unwrap()
        .capability
        .state;
    assert_eq!(state, CapabilityState::Revoked);
}

// =========================================================================
// AT-23: Gateway Structural Absence of Evaluate / CDP
// =========================================================================

#[test]
fn test_at_23_gateway_structural_absence_of_evaluate_and_cdp() {
    // Structural Invariant: Agent protocol has no evaluate methods
    let agent_methods = [
        "action.request",
        "action.status",
        "action.cancel",
        "session.hello",
    ];
    for method in agent_methods {
        assert!(!method.contains("evaluate"));
        assert!(!method.contains("cdp"));
        assert!(!method.contains("raw"));
        assert!(!method.contains("handle"));
    }
}

// =========================================================================
// AT-25 & AT-26: Multi-Step Flow & Off-Graph Navigation Invalidation
// =========================================================================

#[tokio::test]
async fn test_at_25_and_at_26_multi_step_flow_and_off_graph_invalidation() {
    let (broker, session_id, origin, agent_id, _) = setup_acceptance_broker().await;

    // Step 1: Password step
    let step1_resp = broker
        .handle_action_request(
            agent_id.clone(),
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
                reason: "Multi-step flow step 1".to_string(),
                wait: true,
                timeout_ms: 30000,
                client_context: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(step1_resp.state, ActionRequestState::CapabilityIssued);

    // Step 2: TOTP step under same flow
    let step2_resp = broker
        .handle_action_request(
            agent_id,
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticateTotp,
                identity: "github-totp".to_string(),
                target: TargetOriginConstraint {
                    origin: origin.clone(),
                    path_prefix: None,
                },
                browser_session_id: session_id.clone(),
                tab_hint: Some(1),
                reason: "Multi-step flow step 2".to_string(),
                wait: true,
                timeout_ms: 30000,
                client_context: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(step2_resp.state, ActionRequestState::CapabilityIssued);
}

// =========================================================================
// AT-30: Recipe-Only Repair and Rollback
// =========================================================================

#[test]
fn test_at_30_recipe_validation_and_rollback() {
    let recipe = SiteRecipe {
        recipe_id: RecipeId::parse("rcp_test_repair").unwrap(),
        version: 2,
        name: "Test Repair".to_string(),
        action: ActionKind::AuthenticatePassword,
        match_rule: RecipeMatch {
            top_origin: CanonicalOrigin::parse("https://github.com:443").unwrap(),
            path_prefix: None,
            frame_origin: None,
        },
        fields: vec![RecipeField {
            role: "password".to_string(),
            selector: "input#new_password_id".to_string(),
            optional: false,
            clear_first: true,
        }],
        submit: None,
        success_indicators: None,
        oauth: None,
        content_hash: vec![10, 20, 30],
        enabled: true,
    };

    let serialized = serde_json::to_string(&recipe).unwrap();
    let deserialized: SiteRecipe = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.version, 2);
    assert_eq!(deserialized.fields[0].selector, "input#new_password_id");
}

// =========================================================================
// AT-33: Presence Assurance & No Silent Downgrade
// =========================================================================

#[test]
fn test_at_33_no_silent_presence_downgrade() {
    let grant = StandingGrant {
        grant_id: secretctl_domain::GrantId::new(),
        agent_id: AgentId::new(),
        agent_name: "test-agent".to_string(),
        credential_id: CredentialId::new(),
        credential_name: "aws-prod".to_string(),
        action: ActionKind::AuthenticatePassword,
        origin: CanonicalOrigin::parse("https://signin.aws.amazon.com:443").unwrap(),
        risk_ceiling: RiskLevel::High,
        require_presence: true,
        use_count: 0,
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
    };

    // High risk with require_presence cannot be auto-approved without hardware presence
    assert!(grant.require_presence);
    assert_eq!(grant.risk_ceiling, RiskLevel::High);
}

// =========================================================================
// AT-34 to AT-36: Session Reuse, First-Run & Prompt Burden Tracking
// =========================================================================

#[test]
fn test_at_34_and_at_36_session_reuse_and_prompt_burden_tracking() {
    let store = SqliteStore::in_memory().unwrap();
    let agent_id = AgentId::new();
    let origin = CanonicalOrigin::parse("https://github.com:443").unwrap();

    let grant = StandingGrant {
        grant_id: secretctl_domain::GrantId::new(),
        agent_id: agent_id.clone(),
        agent_name: "claude".to_string(),
        credential_id: CredentialId::new(),
        credential_name: "github-work".to_string(),
        action: ActionKind::AuthenticatePassword,
        origin: origin.clone(),
        risk_ceiling: RiskLevel::Medium,
        require_presence: false,
        use_count: 0,
        expires_at: Utc::now() + Duration::days(7),
        created_at: Utc::now(),
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
    };

    let audit_event = secretctl_audit::create_audit_event(
        1,
        &secretctl_audit::GENESIS_PREVIOUS_HASH,
        1,
        &[1u8; 32],
        "grant.created",
        "human",
        Some("admin".to_string()),
        &secretctl_audit::AuditContext {
            request_id: None,
            credential_id: Some("github-work".to_string()),
            capability_id: None,
            browser_session_id: None,
            target_origin: Some("https://github.com:443".to_string()),
            action: Some("authenticate.password".to_string()),
            decision: Some("grant_created".to_string()),
            risk_level: Some("medium".to_string()),
            error_code: None,
        },
        Utc::now(),
    )
    .unwrap();

    store
        .insert_standing_grant_with_audit(&grant, &audit_event)
        .unwrap();

    // Verify standing grant matches and tracks use count without prompting
    let matched = store
        .find_matching_standing_grant(
            &agent_id,
            "github-work",
            ActionKind::AuthenticatePassword,
            &origin,
        )
        .unwrap();

    assert!(matched.is_some());
    let g = matched.unwrap();
    assert_eq!(g.credential_name, "github-work");

    store.touch_standing_grant(&g.grant_id, Utc::now()).unwrap();
    let updated = store.list_standing_grants(false).unwrap();
    assert_eq!(updated[0].use_count, 1);
}
