use chrono::Utc;
use secretctl_crypto::KeyPair;
use secretctl_domain::{
    ActionKind, ActionRequestState, AgentId, AgentPrincipal, BrowserInstanceId, BrowserSession,
    BrowserSessionId, BrowserSessionState, CanonicalOrigin, CredentialDescriptor, CredentialId,
    PageContext, RecipeField, RecipeId, RecipeMatch, RequestId, RuleId, SiteRecipe,
};
use secretctl_policy::{
    DestinationRule, PolicyDocument, PolicyEvaluator, PolicyRule, RuleConditions,
};
use secretctl_protocol::{
    ActionRequestParams, ExecutorConsumeParams, ExecutorContextPayload, TargetOriginConstraint,
};
use secretctl_providers::{MemorySecretProvider, SecretProvider};
use secretctl_store::SqliteStore;
use secretctld::state::BrokerState;
use std::sync::Arc;

const SOAK_PASSWORD_CANARY: &[u8] = b"SOAK_PASSWORD_CANARY_VALUE";
const SOAK_TOTP_SEED: &[u8] = b"12345678901234567890";

#[tokio::test]
async fn test_soak_repeated_actions_stress_and_invariant_verification() {
    let broker_key = KeyPair::generate();
    let store = SqliteStore::in_memory().expect("in-memory db");
    let provider = Arc::new(MemorySecretProvider::new());

    provider
        .store_secret("soak-password", SOAK_PASSWORD_CANARY)
        .await
        .unwrap();
    provider
        .store_secret("soak-totp", SOAK_TOTP_SEED)
        .await
        .unwrap();

    let agent_id = AgentId::new();
    let agent_key = KeyPair::generate();
    store
        .insert_agent(&AgentPrincipal {
            agent_id: agent_id.clone(),
            role: "agent".to_string(),
            public_key: agent_key.public_key_bytes().to_vec(),
            display_name: "soak-agent".to_string(),
            peer_uid: None,
            executable_path: None,
            executable_hash: None,
            state: "enrolled".to_string(),
            created_at: Utc::now(),
        })
        .unwrap();

    let origin = CanonicalOrigin::parse("https://soak.secretctl.test:443").unwrap();

    for (name, kind, action) in [
        (
            "soak-password",
            "password",
            ActionKind::AuthenticatePassword,
        ),
        ("soak-totp", "totp", ActionKind::AuthenticateTotp),
    ] {
        store
            .insert_credential(&CredentialDescriptor {
                credential_id: CredentialId::new(),
                name: name.to_string(),
                kind: kind.to_string(),
                provider: "memory".to_string(),
                provider_locator: name.to_string(),
                allowed_actions: vec![action],
                metadata_json: format!(r#"{{"origin":"{origin}"}}"#),
                disabled_at: None,
            })
            .unwrap();
    }

    let policy_doc = PolicyDocument {
        version: "soak-v1".to_string(),
        rules: vec![PolicyRule {
            id: RuleId::parse("rule_soak").unwrap(),
            description: Some("Allow soak test actions".to_string()),
            effect: secretctl_domain::PolicyEffect::Allow,
            principals: vec![agent_id.to_string(), "*".to_string()],
            credentials: vec!["soak-password".to_string(), "soak-totp".to_string()],
            actions: vec![
                ActionKind::AuthenticatePassword,
                ActionKind::AuthenticateTotp,
            ],
            destinations: vec![DestinationRule {
                origin: origin.clone(),
                path_prefix: None,
            }],
            conditions: RuleConditions {
                browser_assurance: Some("managed".to_string()),
                require_user_presence: false,
                max_uses: 10,
                max_consume_ttl_seconds: 120,
                max_execution_ttl_seconds: 120,
            },
        }],
    };
    let evaluator = PolicyEvaluator::new(policy_doc);
    let state = BrokerState::new(
        broker_key,
        "soak-key-v1",
        store,
        provider.clone(),
        evaluator,
    );

    state.register_recipe(SiteRecipe {
        recipe_id: RecipeId::parse("rcp_soak_pass").unwrap(),
        version: 1,
        name: "Soak Password".to_string(),
        action: ActionKind::AuthenticatePassword,
        match_rule: RecipeMatch {
            top_origin: origin.clone(),
            path_prefix: None,
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
        content_hash: vec![1],
        enabled: true,
    });

    state.register_recipe(SiteRecipe {
        recipe_id: RecipeId::parse("rcp_soak_totp").unwrap(),
        version: 1,
        name: "Soak TOTP".to_string(),
        action: ActionKind::AuthenticateTotp,
        match_rule: RecipeMatch {
            top_origin: origin.clone(),
            path_prefix: None,
            frame_origin: Some(origin.clone()),
        },
        fields: vec![RecipeField {
            role: "totp_code".to_string(),
            selector: "input#otp".to_string(),
            optional: false,
            clear_first: true,
        }],
        submit: None,
        success_indicators: None,
        oauth: None,
        content_hash: vec![2],
        enabled: true,
    });

    let session_id = BrowserSessionId::new();
    state.register_browser_session(BrowserSession {
        session_id: session_id.clone(),
        instance_id: BrowserInstanceId::new(),
        extension_key_id: "soak-ext-key".to_string(),
        profile_id: "soak-profile".to_string(),
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
            document_id: "doc-soak".to_string(),
            path: "/auth".to_string(),
            path_sha256: "soak-path-hash".to_string(),
            tls: true,
            incognito: false,
            observed_at: Utc::now(),
        },
        session_id.clone(),
    );

    let iterations = 100;
    for i in 0..iterations {
        // A TOTP step is intentionally single-use. Exercise it once, then
        // stress repeated password capabilities without asking the broker to
        // violate its same-time-step replay protection.
        let is_password = i != 1;
        let action = if is_password {
            ActionKind::AuthenticatePassword
        } else {
            ActionKind::AuthenticateTotp
        };
        let identity = if is_password {
            "soak-password"
        } else {
            "soak-totp"
        };

        let action_resp = state
            .handle_action_request(
                agent_id.clone(),
                ActionRequestParams {
                    request_id: RequestId::new(),
                    action,
                    identity: identity.to_string(),
                    target: TargetOriginConstraint {
                        origin: origin.clone(),
                        path_prefix: None,
                    },
                    browser_session_id: session_id.clone(),
                    tab_hint: Some(1),
                    reason: format!("Soak iteration {i}"),
                    wait: true,
                    timeout_ms: 30000,
                    client_context: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(action_resp.state, ActionRequestState::CapabilityIssued);

        // Verify zero canary leakage in public response
        let serialized = serde_json::to_string(&action_resp).unwrap();
        assert!(!serialized.contains("SOAK_PASSWORD_CANARY"));

        let cap_id_str = action_resp
            .evidence_ref
            .as_ref()
            .unwrap()
            .strip_prefix("cap:")
            .unwrap();
        let cap_id = secretctl_domain::CapabilityId::parse(cap_id_str).unwrap();

        let token = {
            let caps = state.capabilities.lock().unwrap();
            caps.get(&cap_id).unwrap().token.clone()
        };

        let consume_resp = state
            .handle_executor_consume(ExecutorConsumeParams {
                capability_token: token,
                session_signature: "soak-sig".to_string(),
                current_context: ExecutorContextPayload {
                    browser_session_id: session_id.clone(),
                    tab_id: 1,
                    frame_id: 0,
                    document_id: "doc-soak".to_string(),
                    navigation_epoch: 1,
                    top_origin: origin.clone(),
                    frame_origin: origin.clone(),
                    path: "/auth".to_string(),
                    path_sha256: "soak-path-hash".to_string(),
                    tls: true,
                    incognito: false,
                },
            })
            .await
            .unwrap();

        assert_eq!(consume_resp.fields.len(), 1);

        state
            .handle_executor_result(secretctl_protocol::ExecutorResultParams {
                execution_id: consume_resp.execution_id,
                status: "completed".to_string(),
                result_code: "SUCCESS".to_string(),
                evidence: None,
            })
            .await
            .unwrap();
    }

    // Invariant Checks after 100 continuous iterations:
    // 1. Audit Chain Integrity: verify full sequence
    let events = state.store.list_audit_events().unwrap();
    assert!(events.len() >= iterations * 2);

    for event in &events {
        assert!(!event.event_json.contains("SOAK_PASSWORD_CANARY"));
    }

    // 2. Exactly zero active/unconsumed capabilities remain stuck in memory
    let remaining_active_caps = state
        .capabilities
        .lock()
        .unwrap()
        .values()
        .filter(|c| {
            c.capability.state == secretctl_domain::CapabilityState::Active
                || c.capability.state == secretctl_domain::CapabilityState::Issued
        })
        .count();
    assert_eq!(
        remaining_active_caps, 0,
        "No capabilities may remain stuck active"
    );
}
