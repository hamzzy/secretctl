use chrono::Utc;
use secretctl_crypto::KeyPair;
use secretctl_domain::{
    ActionKind, AgentId, BrowserSession, BrowserSessionId, BrowserSessionState, CanonicalOrigin,
    CredentialDescriptor, CredentialId, PageContext, RecipeField, RecipeId, RecipeMatch, RequestId,
    SiteRecipe,
};
use secretctl_policy::{
    DestinationRule, PolicyDocument, PolicyEvaluator, PolicyRule, RuleConditions,
};
use secretctl_protocol::{
    ActionRequestParams, ExecutorConsumeParams, ExecutorContextPayload, ExecutorPrepareParams,
    ExecutorResultParams, TargetOriginConstraint,
};
use secretctl_providers::{MemorySecretProvider, SecretProvider};
use secretctl_store::SqliteStore;
use secretctld::state::BrokerState;
use std::sync::Arc;

async fn setup_test_broker() -> (BrokerState, BrowserSessionId, CanonicalOrigin) {
    let broker_key = KeyPair::generate();
    let store = SqliteStore::in_memory().expect("in-memory db");
    let provider = Arc::new(MemorySecretProvider::new());
    provider
        .store_secret("github-work", b"super_secret_password_123")
        .await
        .expect("stored secret");
    provider
        .store_secret("github-totp", b"12345678901234567890")
        .await
        .expect("stored totp seed");
    provider
        .store_secret("account-recovery", b"REC-8842-9911-3320")
        .await
        .expect("stored recovery code");

    for (name, kind, action) in [
        ("github-work", "password", ActionKind::AuthenticatePassword),
        ("github-totp", "totp", ActionKind::AuthenticateTotp),
        (
            "account-recovery",
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
                metadata_json: "{}".to_string(),
                disabled_at: None,
            })
            .expect("stored credential metadata");
    }

    let origin = CanonicalOrigin::parse("https://github.com:443").expect("valid origin");

    let rule = PolicyRule {
        id: secretctl_domain::RuleId::parse("rule_github").unwrap(),
        description: Some("Allow github login and totp".to_string()),
        effect: secretctl_domain::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        credentials: vec![
            "github-work".to_string(),
            "github-totp".to_string(),
            "account-recovery".to_string(),
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

    // Register test site recipe
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
        content_hash: vec![4, 5, 6],
        enabled: true,
    });
    state.register_recipe(SiteRecipe {
        recipe_id: RecipeId::parse("rcp_account_recovery").unwrap(),
        version: 1,
        name: "Account recovery".to_string(),
        action: ActionKind::FormSensitiveFill,
        match_rule: RecipeMatch {
            top_origin: origin.clone(),
            path_prefix: None,
            frame_origin: Some(origin.clone()),
        },
        fields: vec![RecipeField {
            role: "recovery_code".to_string(),
            selector: "input[name='recovery_code']".to_string(),
            optional: false,
            clear_first: true,
        }],
        submit: None,
        success_indicators: None,
        content_hash: vec![7, 8, 9],
        enabled: true,
    });

    // Register active browser session
    let session_id = BrowserSessionId::new();
    let session = BrowserSession {
        session_id: session_id.clone(),
        instance_id: secretctl_domain::BrowserInstanceId::new(),
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

    (state, session_id, origin)
}

#[tokio::test]
async fn test_full_fake_executor_flow_success() {
    let (broker, session_id, origin) = setup_test_broker().await;
    let agent_id = AgentId::new();
    let request_id = RequestId::new();

    // 1. Agent requests action
    let agent_req = ActionRequestParams {
        request_id: request_id.clone(),
        action: ActionKind::AuthenticatePassword,
        identity: "github-work".to_string(),
        target: TargetOriginConstraint {
            origin: origin.clone(),
            path_prefix: Some("/login".to_string()),
        },
        browser_session_id: session_id.clone(),
        tab_hint: Some(1),
        reason: "Test login flow".to_string(),
        wait: true,
        timeout_ms: 30000,
        client_context: None,
    };

    let agent_resp = broker
        .handle_action_request(agent_id, agent_req)
        .await
        .expect("action request should succeed");

    assert_eq!(
        agent_resp.state,
        secretctl_domain::ActionRequestState::CapabilityIssued
    );
    // Security check: Zero secrets in agent response!
    let serialized_agent_resp = serde_json::to_string(&agent_resp).unwrap();
    assert!(!serialized_agent_resp.contains("super_secret"));
    assert!(!serialized_agent_resp.contains("password"));

    // 2. Executor prepares context
    let prep_context = ExecutorContextPayload {
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

    let prep_resp = broker
        .handle_executor_prepare(ExecutorPrepareParams {
            context: prep_context.clone(),
        })
        .await
        .expect("executor prepare should succeed");

    assert!(prep_resp.prepared);
    assert!(!prep_resp.matching_recipes.is_empty());

    // 3. Obtain capability token from broker state
    let token = {
        let caps = broker.capabilities.lock().unwrap();
        caps.values().next().unwrap().token.clone()
    };

    // 4. Executor consumes capability
    let consume_params = ExecutorConsumeParams {
        capability_token: token.clone(),
        session_signature: "mock-sig".to_string(),
        current_context: prep_context,
    };

    let consume_resp = broker
        .handle_executor_consume(consume_params)
        .await
        .expect("consume should succeed");

    assert_eq!(consume_resp.fields.len(), 1);
    assert_eq!(
        consume_resp.fields[0].encrypted_value,
        "super_secret_password_123"
    );

    // 5. Executor reports result
    let result_params = ExecutorResultParams {
        execution_id: consume_resp.execution_id,
        status: "completed".to_string(),
        result_code: "LOGIN_SUCCESS".to_string(),
        evidence: None,
    };

    let result_resp = broker
        .handle_executor_result(result_params)
        .await
        .expect("result report should succeed");

    assert!(result_resp.acknowledged);
}

#[tokio::test]
async fn test_agent_path_constraint_cannot_override_measured_page_path() {
    let (broker, session_id, origin) = setup_test_broker().await;
    broker.register_page_context(
        PageContext {
            tab_id: 1,
            frame_id: 0,
            top_origin: origin.clone(),
            frame_origin: origin.clone(),
            navigation_epoch: 2,
            document_id: "doc-2".to_string(),
            path: "/settings/security".to_string(),
            path_sha256: "different-path-hash".to_string(),
            tls: true,
            incognito: false,
            observed_at: Utc::now(),
        },
        session_id.clone(),
    );

    let result = broker
        .handle_action_request(
            AgentId::new(),
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin,
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: session_id,
                tab_hint: Some(1),
                reason: "Attempt to override measured path".to_string(),
                wait: true,
                timeout_ms: 30_000,
                client_context: None,
            },
        )
        .await;

    let error = result.expect_err("measured path mismatch must fail closed");
    assert_eq!(
        error.code,
        secretctl_protocol::RpcErrorCode::ORIGIN_MISMATCH.0
    );
    assert!(broker.capabilities.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_concurrent_consume_race_condition() {
    let (broker, session_id, origin) = setup_test_broker().await;
    let agent_id = AgentId::new();
    let request_id = RequestId::new();

    // 1. Issue capability
    let agent_req = ActionRequestParams {
        request_id: request_id.clone(),
        action: ActionKind::AuthenticatePassword,
        identity: "github-work".to_string(),
        target: TargetOriginConstraint {
            origin: origin.clone(),
            path_prefix: Some("/login".to_string()),
        },
        browser_session_id: session_id.clone(),
        tab_hint: Some(1),
        reason: "Test concurrent race".to_string(),
        wait: true,
        timeout_ms: 30000,
        client_context: None,
    };

    broker
        .handle_action_request(agent_id, agent_req)
        .await
        .unwrap();

    let token = {
        let caps = broker.capabilities.lock().unwrap();
        caps.values().next().unwrap().token.clone()
    };

    let context = ExecutorContextPayload {
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

    // 2. Launch 100 concurrent consume attempts (AT-06)
    let mut handles = Vec::new();
    for _ in 0..100 {
        let b = broker.clone();
        let t = token.clone();
        let ctx = context.clone();
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

    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => success_count += 1,
            Err(err) => {
                assert_eq!(
                    err.code,
                    secretctl_protocol::RpcErrorCode::CAPABILITY_CONSUMED.0
                );
                failure_count += 1;
            }
        }
    }

    // Atomic invariant: exactly 1 winner, 99 rejected
    assert_eq!(success_count, 1);
    assert_eq!(failure_count, 99);
    assert_eq!(broker.store.execution_count().unwrap(), 1);
    assert_eq!(
        broker
            .store
            .list_audit_events()
            .unwrap()
            .iter()
            .filter(|event| event.event_type == "capability.consumed")
            .count(),
        1
    );
}

#[tokio::test]
async fn test_epoch_invalidation_fails_closed() {
    let (broker, session_id, origin) = setup_test_broker().await;
    let agent_id = AgentId::new();

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
                reason: "Epoch test".to_string(),
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

    // Attempt consume with changed navigation epoch (e.g. 2 instead of 1)
    let bad_context = ExecutorContextPayload {
        browser_session_id: session_id.clone(),
        tab_id: 1,
        frame_id: 0,
        document_id: "doc-1".to_string(),
        navigation_epoch: 2, // Mismatch!
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
    assert_eq!(
        err.code,
        secretctl_protocol::RpcErrorCode::EPOCH_INVALIDATED.0
    );
}

#[tokio::test]
async fn test_totp_execution_flow() {
    let (broker, session_id, origin) = setup_test_broker().await;
    let agent_id = AgentId::new();
    let request_id = RequestId::new();

    // 1. Agent requests TOTP
    let agent_req = ActionRequestParams {
        request_id: request_id.clone(),
        action: ActionKind::AuthenticateTotp,
        identity: "github-totp".to_string(),
        target: TargetOriginConstraint {
            origin: origin.clone(),
            path_prefix: None,
        },
        browser_session_id: session_id.clone(),
        tab_hint: Some(1),
        reason: "Two factor check".to_string(),
        wait: true,
        timeout_ms: 30000,
        client_context: None,
    };

    let agent_resp = broker
        .handle_action_request(agent_id, agent_req)
        .await
        .expect("TOTP action request should succeed");

    assert_eq!(
        agent_resp.state,
        secretctl_domain::ActionRequestState::CapabilityIssued
    );

    let token = {
        let caps = broker.capabilities.lock().unwrap();
        caps.values().next().unwrap().token.clone()
    };

    let context = ExecutorContextPayload {
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

    // 2. Executor consumes capability and receives OTP code (never seed!)
    let consume_resp = broker
        .handle_executor_consume(ExecutorConsumeParams {
            capability_token: token,
            session_signature: "mock-sig".to_string(),
            current_context: context,
        })
        .await
        .expect("consume should succeed");

    assert_eq!(consume_resp.fields.len(), 1);
    assert_eq!(consume_resp.fields[0].role, "totp_code");
    assert_eq!(consume_resp.fields[0].encrypted_value.len(), 6);
    assert!(
        consume_resp.fields[0]
            .encrypted_value
            .chars()
            .all(|c| c.is_ascii_digit())
    );
}

#[tokio::test]
async fn test_sensitive_form_fill_flow() {
    let (broker, session_id, origin) = setup_test_broker().await;
    let agent_id = AgentId::new();
    let request_id = RequestId::new();

    // 1. Agent requests form fill
    let agent_req = ActionRequestParams {
        request_id: request_id.clone(),
        action: ActionKind::FormSensitiveFill,
        identity: "account-recovery".to_string(),
        target: TargetOriginConstraint {
            origin: origin.clone(),
            path_prefix: None,
        },
        browser_session_id: session_id.clone(),
        tab_hint: Some(1),
        reason: "Sensitive form fill".to_string(),
        wait: true,
        timeout_ms: 30000,
        client_context: None,
    };

    let agent_resp = broker
        .handle_action_request(agent_id, agent_req)
        .await
        .expect("form fill request should succeed");

    assert_eq!(
        agent_resp.state,
        secretctl_domain::ActionRequestState::CapabilityIssued
    );

    let token = {
        let caps = broker.capabilities.lock().unwrap();
        caps.values().next().unwrap().token.clone()
    };

    let context = ExecutorContextPayload {
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

    // 2. Executor consumes capability
    let consume_resp = broker
        .handle_executor_consume(ExecutorConsumeParams {
            capability_token: token,
            session_signature: "mock-sig".to_string(),
            current_context: context,
        })
        .await
        .expect("consume should succeed");

    assert_eq!(consume_resp.fields.len(), 1);
    assert_eq!(consume_resp.fields[0].role, "recovery_code");
    assert_eq!(consume_resp.fields[0].encrypted_value, "REC-8842-9911-3320");
}

#[tokio::test]
async fn test_stale_heartbeat_revokes_session_capabilities() {
    let (broker, session_id, origin) = setup_test_broker().await;
    broker
        .handle_action_request(
            AgentId::new(),
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin,
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: session_id,
                tab_hint: Some(1),
                reason: "heartbeat revocation".to_string(),
                wait: true,
                timeout_ms: 30_000,
                client_context: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        broker
            .expire_stale_sessions(Utc::now() + chrono::Duration::seconds(11))
            .unwrap(),
        1
    );
    let capabilities = broker.capabilities.lock().unwrap();
    assert!(capabilities.values().all(|entry| {
        entry.capability.state == secretctl_domain::CapabilityState::Revoked
            && entry.capability.revoked_reason.as_deref() == Some("session_stale")
    }));
}

#[tokio::test]
async fn test_policy_reload_revokes_old_policy_capabilities() {
    let (broker, session_id, origin) = setup_test_broker().await;
    broker
        .handle_action_request(
            AgentId::new(),
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin,
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: session_id,
                tab_hint: Some(1),
                reason: "policy reload".to_string(),
                wait: true,
                timeout_ms: 30_000,
                client_context: None,
            },
        )
        .await
        .unwrap();
    let new_policy = PolicyEvaluator::new(PolicyDocument {
        version: "1.1".to_string(),
        rules: vec![],
    });
    assert_eq!(broker.replace_policy(new_policy).unwrap(), 1);
    let capabilities = broker.capabilities.lock().unwrap();
    assert!(capabilities.values().all(|entry| {
        entry.capability.state == secretctl_domain::CapabilityState::Revoked
            && entry.capability.revoked_reason.as_deref() == Some("policy_changed")
    }));
    drop(capabilities);
    assert!(
        broker
            .store
            .list_capabilities(Some("revoked"))
            .unwrap()
            .iter()
            .all(|capability| capability.revoked_reason.as_deref() == Some("policy_changed"))
    );
}

#[tokio::test]
async fn test_required_approval_denial_never_mints_capability() {
    let (broker, session_id, origin) = setup_test_broker().await;
    broker
        .replace_policy(PolicyEvaluator::new(PolicyDocument {
            version: "approval-required".to_string(),
            rules: vec![PolicyRule {
                id: secretctl_domain::RuleId::parse("rule_presence").unwrap(),
                description: None,
                effect: secretctl_domain::PolicyEffect::Allow,
                principals: vec!["*".to_string()],
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
                    max_ttl_seconds: 30,
                },
            }],
        }))
        .unwrap();
    let response = broker
        .handle_action_request(
            AgentId::new(),
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin,
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: session_id,
                tab_hint: Some(1),
                reason: "approval denial".to_string(),
                wait: false,
                timeout_ms: 30_000,
                client_context: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        response.state,
        secretctl_domain::ActionRequestState::AwaitingApproval
    );

    let approval = broker.list_pending_approvals().pop().unwrap();
    let denied = broker
        .decide_approval(
            &approval.approval_id,
            false,
            &approval.context_digest,
            "test-user",
            true,
        )
        .unwrap();
    assert_eq!(denied.state, secretctl_domain::ActionRequestState::Denied);
    assert!(broker.capabilities.lock().unwrap().is_empty());
    assert!(
        broker
            .store
            .list_audit_events()
            .unwrap()
            .iter()
            .any(|event| event.event_type == "approval.denied")
    );
}

#[tokio::test]
async fn test_approval_timeout_retrieves_no_secret_and_is_audited() {
    let (broker, session_id, origin) = setup_test_broker().await;
    broker
        .replace_policy(PolicyEvaluator::new(PolicyDocument {
            version: "approval-timeout".to_string(),
            rules: vec![PolicyRule {
                id: secretctl_domain::RuleId::parse("rule_timeout").unwrap(),
                description: None,
                effect: secretctl_domain::PolicyEffect::Allow,
                principals: vec!["*".to_string()],
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
                    max_ttl_seconds: 30,
                },
            }],
        }))
        .unwrap();
    let response = broker
        .handle_action_request(
            AgentId::new(),
            ActionRequestParams {
                request_id: RequestId::new(),
                action: ActionKind::AuthenticatePassword,
                identity: "github-work".to_string(),
                target: TargetOriginConstraint {
                    origin,
                    path_prefix: Some("/login".to_string()),
                },
                browser_session_id: session_id,
                tab_hint: Some(1),
                reason: "approval timeout".to_string(),
                wait: false,
                timeout_ms: 30_000,
                client_context: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        response.state,
        secretctl_domain::ActionRequestState::AwaitingApproval
    );
    assert_eq!(
        broker
            .expire_pending_approvals(Utc::now() + chrono::Duration::seconds(61))
            .unwrap(),
        1
    );
    assert!(broker.capabilities.lock().unwrap().is_empty());
    assert!(
        broker
            .store
            .list_audit_events()
            .unwrap()
            .iter()
            .any(|event| event.event_type == "approval.expired")
    );
}

#[tokio::test]
async fn test_audit_storage_failure_rolls_back_consume_before_secret_retrieval() {
    let (broker, session_id, origin) = setup_test_broker().await;
    broker
        .handle_action_request(
            AgentId::new(),
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
                reason: "audit failure".to_string(),
                wait: false,
                timeout_ms: 30_000,
                client_context: None,
            },
        )
        .await
        .unwrap();
    let (capability_id, token) = {
        let capabilities = broker.capabilities.lock().unwrap();
        let entry = capabilities.values().next().unwrap();
        (entry.capability.capability_id.clone(), entry.token.clone())
    };
    broker
        .store
        .install_audit_failure_trigger_for_tests()
        .unwrap();
    let result = broker
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
                frame_origin: origin,
                path: "/login".to_string(),
                path_sha256: "path-hash".to_string(),
                tls: true,
                incognito: false,
            },
        })
        .await;
    assert!(result.is_err());
    assert_eq!(
        broker.store.capability_state(&capability_id).unwrap(),
        "issued"
    );
    assert_eq!(broker.store.execution_count().unwrap(), 0);
    assert_eq!(
        broker
            .capabilities
            .lock()
            .unwrap()
            .get(&capability_id)
            .unwrap()
            .capability
            .state,
        secretctl_domain::CapabilityState::Issued
    );
    broker.verify_audit_integrity().unwrap();
}

#[tokio::test]
async fn test_restart_marks_consuming_execution_indeterminate_and_never_reissues() {
    let (broker, session_id, origin) = setup_test_broker().await;
    broker
        .handle_action_request(
            AgentId::new(),
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
                reason: "restart recovery".to_string(),
                wait: false,
                timeout_ms: 30_000,
                client_context: None,
            },
        )
        .await
        .unwrap();
    let (capability_id, token) = {
        let capabilities = broker.capabilities.lock().unwrap();
        let entry = capabilities.values().next().unwrap();
        (entry.capability.capability_id.clone(), entry.token.clone())
    };
    broker
        .handle_executor_consume(ExecutorConsumeParams {
            capability_token: token,
            session_signature: "authenticated-channel".to_string(),
            current_context: ExecutorContextPayload {
                browser_session_id: session_id,
                tab_id: 1,
                frame_id: 0,
                document_id: "doc-1".to_string(),
                navigation_epoch: 1,
                top_origin: origin.clone(),
                frame_origin: origin,
                path: "/login".to_string(),
                path_sha256: "path-hash".to_string(),
                tls: true,
                incognito: false,
            },
        })
        .await
        .unwrap();

    let store = broker.store.clone();
    assert_eq!(store.capability_state(&capability_id).unwrap(), "consumed");
    assert_eq!(
        store
            .execution_state_for_capability(&capability_id)
            .unwrap(),
        "consuming"
    );

    let _restarted = BrokerState::try_new_with_audit_key(
        KeyPair::generate(),
        "restart-key",
        secretctl_crypto::SecretBytes::new(vec![7; 32]),
        1,
        store.clone(),
        Arc::new(MemorySecretProvider::new()),
        PolicyEvaluator::new(PolicyDocument {
            version: "1.0".to_string(),
            rules: vec![],
        }),
    )
    .unwrap();
    assert_eq!(store.capability_state(&capability_id).unwrap(), "consumed");
    assert_eq!(
        store
            .execution_state_for_capability(&capability_id)
            .unwrap(),
        "indeterminate"
    );
}

#[tokio::test]
async fn test_request_id_is_idempotent_and_conflicts_fail_closed() {
    let (broker, session_id, origin) = setup_test_broker().await;
    let agent_id = AgentId::new();
    let request_id = RequestId::new();
    let params = ActionRequestParams {
        request_id: request_id.clone(),
        action: ActionKind::AuthenticatePassword,
        identity: "github-work".to_string(),
        target: TargetOriginConstraint {
            origin,
            path_prefix: Some("/login".to_string()),
        },
        browser_session_id: session_id,
        tab_hint: Some(1),
        reason: "idempotency".to_string(),
        wait: false,
        timeout_ms: 30_000,
        client_context: None,
    };
    let first = broker
        .handle_action_request(agent_id.clone(), params.clone())
        .await
        .unwrap();
    let second = broker
        .handle_action_request(agent_id.clone(), params.clone())
        .await
        .unwrap();
    assert_eq!(first.evidence_ref, second.evidence_ref);
    assert_eq!(broker.capabilities.lock().unwrap().len(), 1);

    let mut conflicting = params;
    conflicting.reason = "changed".to_string();
    let error = broker
        .handle_action_request(agent_id, conflicting)
        .await
        .unwrap_err();
    assert_eq!(error.message, "request_id_conflict");
}
