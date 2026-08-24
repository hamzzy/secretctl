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
use secretctl_protocol::{ActionRequestParams, TargetOriginConstraint};
use secretctl_providers::{MemorySecretProvider, SecretProvider};
use secretctl_store::SqliteStore;
use secretctld::state::BrokerState;
use std::sync::Arc;
use std::time::Instant;

#[tokio::test]
async fn test_benchmark_policy_decision_budget_p95_under_5ms_at_1000_rules() {
    // Generate synthetic 1,000-rule policy document
    let mut rules = Vec::with_capacity(1000);
    for i in 0..1000 {
        rules.push(PolicyRule {
            id: RuleId::parse(&format!("rule_{i:04}")).unwrap(),
            description: Some(format!("Synthetic rule {i}")),
            effect: if i == 999 {
                secretctl_domain::PolicyEffect::Allow
            } else {
                secretctl_domain::PolicyEffect::Deny
            },
            principals: vec![format!("agent_{i}")],
            credentials: vec![format!("credential_{i}")],
            actions: vec![ActionKind::AuthenticatePassword],
            destinations: vec![DestinationRule {
                origin: CanonicalOrigin::parse(&format!("https://app{i}.example.com:443")).unwrap(),
                path_prefix: None,
            }],
            conditions: RuleConditions {
                browser_assurance: Some("managed".to_string()),
                require_user_presence: false,
                max_uses: 1,
                max_consume_ttl_seconds: 30,
                max_execution_ttl_seconds: 120,
            },
        });
    }

    let policy_doc = PolicyDocument {
        version: "bench-1.0".to_string(),
        rules,
    };
    let evaluator = PolicyEvaluator::new(policy_doc);
    let agent_id = AgentId::new();
    let origin = CanonicalOrigin::parse("https://app999.example.com:443").unwrap();

    let mut latencies = Vec::with_capacity(200);
    for _ in 0..200 {
        let start = Instant::now();
        let _ = evaluator.evaluate(
            &agent_id,
            "credential_999",
            ActionKind::AuthenticatePassword,
            &origin,
            None,
            "managed",
        );
        latencies.push(start.elapsed());
    }

    latencies.sort();
    let p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
    println!("Policy evaluation at 1,000 rules: p95 = {:?}", p95);
    // Budget: p95 < 5ms
    assert!(
        p95.as_millis() < 5,
        "Policy evaluation p95 must be < 5ms (was {:?})",
        p95
    );
}

#[tokio::test]
async fn test_benchmark_capability_mint_and_verify_roundtrip_budget_under_10ms() {
    let keypair = KeyPair::generate();
    let origin = CanonicalOrigin::parse("https://github.com:443").unwrap();

    let mut latencies = Vec::with_capacity(200);
    for _ in 0..200 {
        let start = Instant::now();
        let (cap, token) = secretctl_capability::token::mint_capability(
            &keypair,
            "broker-v1",
            RequestId::new(),
            AgentId::new(),
            CredentialId::new(),
            ActionKind::AuthenticatePassword,
            origin.clone(),
            origin.clone(),
            BrowserSessionId::new(),
            "ext-key-1".to_string(),
            1,
            0,
            "doc-1".to_string(),
            1,
            RecipeId::parse("rcp_test").unwrap(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            Utc::now(),
            secretctl_domain::CapabilityDeadlines {
                consume_ttl_seconds: 60,
                execution_ttl_seconds: 120,
                step_ttl_seconds: None,
            },
            None,
            1,
        );

        let verified = secretctl_capability::token::parse_and_verify_token(
            &token,
            &keypair.public_key_bytes(),
        )
        .unwrap();
        assert_eq!(verified.jti, cap.capability_id);
        latencies.push(start.elapsed());
    }

    latencies.sort();
    let p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
    println!("Capability mint + verify roundtrip: p95 = {:?}", p95);
    // Budget: p95 < 10ms
    assert!(
        p95.as_millis() < 10,
        "Capability mint + verify p95 must be < 10ms (was {:?})",
        p95
    );
}

#[tokio::test]
async fn test_benchmark_agent_rpc_latency_budget_under_50ms() {
    let broker_key = KeyPair::generate();
    let store = SqliteStore::in_memory().unwrap();
    let provider = Arc::new(MemorySecretProvider::new());
    provider
        .store_secret("bench-pass", b"bench_pass_123")
        .await
        .unwrap();

    let agent_id = AgentId::new();
    let agent_key = KeyPair::generate();
    store
        .insert_agent(&AgentPrincipal {
            agent_id: agent_id.clone(),
            role: "agent".to_string(),
            public_key: agent_key.public_key_bytes().to_vec(),
            display_name: "bench-agent".to_string(),
            peer_uid: None,
            executable_path: None,
            executable_hash: None,
            state: "enrolled".to_string(),
            created_at: Utc::now(),
        })
        .unwrap();

    let origin = CanonicalOrigin::parse("https://bench.test:443").unwrap();
    store
        .insert_credential(&CredentialDescriptor {
            credential_id: CredentialId::new(),
            name: "bench-pass".to_string(),
            kind: "password".to_string(),
            provider: "memory".to_string(),
            provider_locator: "bench-pass".to_string(),
            allowed_actions: vec![ActionKind::AuthenticatePassword],
            metadata_json: format!(r#"{{"origin":"{origin}"}}"#),
            disabled_at: None,
        })
        .unwrap();

    let policy_doc = PolicyDocument {
        version: "bench".to_string(),
        rules: vec![PolicyRule {
            id: RuleId::parse("rule_bench").unwrap(),
            description: None,
            effect: secretctl_domain::PolicyEffect::Allow,
            principals: vec![agent_id.to_string()],
            credentials: vec!["bench-pass".to_string()],
            actions: vec![ActionKind::AuthenticatePassword],
            destinations: vec![DestinationRule {
                origin: origin.clone(),
                path_prefix: None,
            }],
            conditions: RuleConditions {
                browser_assurance: Some("managed".to_string()),
                require_user_presence: false,
                max_uses: 10,
                max_consume_ttl_seconds: 60,
                max_execution_ttl_seconds: 120,
            },
        }],
    };

    let evaluator = PolicyEvaluator::new(policy_doc);
    let state = BrokerState::new(broker_key, "bench-key", store, provider, evaluator);

    state.register_recipe(SiteRecipe {
        recipe_id: RecipeId::parse("rcp_bench").unwrap(),
        version: 1,
        name: "Bench Recipe".to_string(),
        action: ActionKind::AuthenticatePassword,
        match_rule: RecipeMatch {
            top_origin: origin.clone(),
            path_prefix: None,
            frame_origin: None,
        },
        fields: vec![RecipeField {
            role: "password".to_string(),
            selector: "input#p".to_string(),
            optional: false,
            clear_first: true,
        }],
        submit: None,
        success_indicators: None,
        oauth: None,
        content_hash: vec![1],
        enabled: true,
    });

    let session_id = BrowserSessionId::new();
    state.register_browser_session(BrowserSession {
        session_id: session_id.clone(),
        instance_id: BrowserInstanceId::new(),
        extension_key_id: "ext-bench".to_string(),
        profile_id: "p-bench".to_string(),
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
            document_id: "doc-bench".to_string(),
            path: "/login".to_string(),
            path_sha256: "bench-hash".to_string(),
            tls: true,
            incognito: false,
            observed_at: Utc::now(),
        },
        session_id.clone(),
    );

    let mut latencies = Vec::with_capacity(100);
    for _ in 0..100 {
        let req_id = RequestId::new();
        let start = Instant::now();
        let resp = state
            .handle_action_request(
                agent_id.clone(),
                ActionRequestParams {
                    request_id: req_id,
                    action: ActionKind::AuthenticatePassword,
                    identity: "bench-pass".to_string(),
                    target: TargetOriginConstraint {
                        origin: origin.clone(),
                        path_prefix: None,
                    },
                    browser_session_id: session_id.clone(),
                    tab_hint: Some(1),
                    reason: "Benchmark request".to_string(),
                    wait: true,
                    timeout_ms: 30000,
                    client_context: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.state, ActionRequestState::CapabilityIssued);
        latencies.push(start.elapsed());
    }

    latencies.sort();
    let p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
    println!("Agent RPC request latency: p95 = {:?}", p95);
    // Budget: p95 < 50ms
    assert!(
        p95.as_millis() < 50,
        "Agent RPC latency p95 must be < 50ms (was {:?})",
        p95
    );
}
