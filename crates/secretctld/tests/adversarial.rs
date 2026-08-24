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

async fn setup_adversarial_broker() -> (
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
            max_consume_ttl_seconds: 30,
            max_execution_ttl_seconds: 120,
        },
    };

    let policy_doc = PolicyDocument {
        version: "1.0".to_string(),
        rules: vec![rule],
    };
    let evaluator = PolicyEvaluator::new(policy_doc);

    let state = BrokerState::new(broker_key, "key-test-1", store, provider.clone(), evaluator);

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
        oauth: None,
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

    (state, session_id, origin, agent_id, provider)
}

#[tokio::test]
async fn test_attack_1_malicious_origin_spoofing_denied() {
    let (broker, session_id, _, agent_id, provider) = setup_adversarial_broker().await;
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
    assert_eq!(provider.retrieval_count(), 0);
}

#[tokio::test]
async fn test_attack_2_navigation_epoch_tamper_fails_closed() {
    let (broker, session_id, origin, agent_id, _) = setup_adversarial_broker().await;

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
    let (broker, session_id, origin, agent_id, _) = setup_adversarial_broker().await;

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
    let (broker, session_id, origin, agent_id, _) = setup_adversarial_broker().await;

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

// ---------------------------------------------------------------------------
// Observation surface (page.read_text / page.snapshot_safe / locators)
//
// The gateway gained the ability to let an agent see a page. These tests exist
// to hold the line that seeing a page is not the same as seeing what was typed
// into it.
// ---------------------------------------------------------------------------

mod observation {
    use secretctld::dom_view::{PageProjection, ResolveError, ViewLimits, node_is_protected};
    use serde_json::{Value, json};

    const CANARY: &str = "CANARY-PASSWORD-7f3a91";

    fn element(tag: &str, node_id: u64, attributes: &[(&str, &str)], children: Value) -> Value {
        let attrs: Vec<Value> = attributes
            .iter()
            .flat_map(|(name, value)| {
                [
                    Value::String((*name).into()),
                    Value::String((*value).into()),
                ]
            })
            .collect();
        json!({
            "nodeId": node_id,
            "nodeType": 1,
            "nodeName": tag.to_uppercase(),
            "attributes": attrs,
            "children": children,
        })
    }

    fn text(value: &str) -> Value {
        json!({"nodeType": 3, "nodeValue": value})
    }

    fn assert_canary_free(projection: &PageProjection) {
        let serialized = serde_json::to_string(&projection.nodes).unwrap();
        assert!(
            !serialized.contains(CANARY),
            "canary reached the element projection: {serialized}"
        );
        assert!(
            !projection.text.contains(CANARY),
            "canary reached the text projection: {}",
            projection.text
        );
    }

    /// A filled password lives in the element's `value` property, not the DOM,
    /// but a page is free to mirror it into the `value` attribute. It must not
    /// come back out through either the element list or the text read.
    #[test]
    fn filled_password_mirrored_into_the_value_attribute_does_not_escape() {
        let page = element(
            "form",
            1,
            &[],
            json!([element(
                "input",
                2,
                &[
                    ("type", "password"),
                    ("name", "password"),
                    ("value", CANARY)
                ],
                json!([])
            )]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_canary_free(&projection);
        assert!(projection.nodes[0].protected);
    }

    /// The page echoes the credential into visible text after submission.
    #[test]
    fn credential_echoed_into_a_protected_container_is_elided() {
        let page = element(
            "div",
            1,
            &[],
            json!([
                element("p", 2, &[], json!([text("Signed in")])),
                element(
                    "pre",
                    3,
                    &[("id", "debug-password-echo")],
                    json!([text(CANARY)])
                ),
            ]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_canary_free(&projection);
        assert_eq!(projection.text, "Signed in");
    }

    /// An attacker-controlled page tries to smuggle the credential out as an
    /// element's accessible name, which is the one page-authored string the
    /// projection does return.
    #[test]
    fn credential_smuggled_through_labels_of_a_protected_field_is_dropped() {
        for attribute in ["aria-label", "placeholder", "title", "value"] {
            let page = element(
                "input",
                1,
                &[("type", "password"), (attribute, CANARY)],
                json!([]),
            );
            let projection = PageProjection::from_node(&page, &ViewLimits::default());
            assert_canary_free(&projection);
        }
    }

    /// The credential is placed in a script tag, an inline style, and a hidden
    /// input — three places a DOM dump would surface it.
    #[test]
    fn credential_in_non_content_and_hidden_nodes_is_never_read() {
        let page = element(
            "body",
            1,
            &[],
            json!([
                element("script", 2, &[], json!([text(CANARY)])),
                element("style", 3, &[], json!([text(CANARY)])),
                element(
                    "input",
                    4,
                    &[("type", "hidden"), ("name", "csrf"), ("value", CANARY)],
                    json!([])
                ),
                element("p", 5, &[], json!([text("Welcome")])),
            ]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_canary_free(&projection);
        assert_eq!(projection.text, "Welcome");
    }

    /// An OTP field named innocuously still has to be recognised, because the
    /// autocomplete hint is what a real site uses.
    #[test]
    fn one_time_code_fields_are_protected_however_they_are_named() {
        for attributes in [
            vec![("type", "text"), ("autocomplete", "one-time-code")],
            vec![("type", "text"), ("name", "totp")],
            vec![("type", "text"), ("data-testid", "otp-input")],
            vec![
                ("type", "text"),
                ("autocomplete", "section-login one-time-code"),
            ],
        ] {
            let page = element("input", 1, &attributes, json!([]));
            let projection = PageProjection::from_node(&page, &ViewLimits::default());
            assert!(
                projection.nodes[0].protected,
                "not protected: {attributes:?}"
            );
        }
    }

    /// The projection and the typing guard must agree about what is protected.
    /// If they disagree, an agent could type into a field the projection told
    /// it was ordinary.
    #[test]
    fn projection_and_typing_guard_agree_on_protected_fields() {
        let cases: Vec<Vec<(&str, &str)>> = vec![
            vec![("type", "password")],
            vec![("type", "text"), ("autocomplete", "current-password")],
            vec![("type", "text"), ("name", "user_token")],
            vec![("type", "text"), ("id", "cvv")],
            vec![("type", "text"), ("name", "username")],
            vec![("type", "email")],
        ];
        for attributes in cases {
            let node = element("input", 1, &attributes, json!([]));
            let projection = PageProjection::from_node(&node, &ViewLimits::default());
            let via_projection = projection.nodes[0].protected;
            let via_guard = node_is_protected(&json!({"node": node}));
            assert_eq!(
                via_projection, via_guard,
                "projection and typing guard disagree for {attributes:?}"
            );
        }
    }

    /// A page that mutates between snapshot and action must not be able to
    /// redirect the action onto a different control.
    #[test]
    fn a_reference_cannot_be_redirected_onto_a_swapped_control() {
        let before = element(
            "div",
            1,
            &[],
            json!([element("button", 2, &[], json!([text("Sign in")]))]),
        );
        let snapshot = PageProjection::from_node(&before, &ViewLimits::default());
        let reference = snapshot.nodes[0].reference.clone();

        // Same position, different control.
        let after = element(
            "div",
            1,
            &[],
            json!([element(
                "button",
                2,
                &[],
                json!([text("Delete everything")])
            )]),
        );
        let after = PageProjection::from_node(&after, &ViewLimits::default());
        assert_eq!(
            after.resolve_reference(&reference),
            Err(ResolveError::Stale)
        );
    }

    /// Two identical controls must fail rather than resolve to the first one.
    #[test]
    fn a_decoy_control_makes_a_locator_ambiguous_rather_than_wrong() {
        let page = element(
            "div",
            1,
            &[],
            json!([
                element("button", 2, &[], json!([text("Confirm")])),
                element("button", 3, &[], json!([text("Confirm")])),
            ]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_eq!(
            projection.resolve_role("button", "Confirm"),
            Err(ResolveError::Ambiguous)
        );
    }

    /// An agent must not be able to enlarge its own view of a page.
    #[test]
    fn an_agent_cannot_raise_its_own_observation_limits() {
        let limits = ViewLimits::clamped(Some(usize::MAX), Some(usize::MAX));
        assert_eq!(limits.max_nodes, 250);
        assert_eq!(limits.max_chars, 20_000);

        let children: Vec<Value> = (0..500)
            .map(|index| element("button", index + 2, &[], json!([text("Go")])))
            .collect();
        let page = element("div", 1, &[], Value::Array(children));
        let projection = PageProjection::from_node(&page, &limits);
        assert_eq!(projection.nodes.len(), 250);
        assert!(projection.nodes_truncated);
    }

    /// Content inside an iframe belongs to a different origin and must not be
    /// presented to the agent as part of the top-level page.
    #[test]
    fn a_hostile_iframe_cannot_inject_content_into_the_top_page_view() {
        let mut frame = element("iframe", 2, &[("src", "https://evil.test/")], json!([]));
        frame["contentDocument"] = element(
            "body",
            3,
            &[],
            json!([
                element("button", 4, &[], json!([text("Sign in")])),
                element("p", 5, &[], json!([text(CANARY)])),
            ]),
        );
        let page = element(
            "div",
            1,
            &[],
            json!([frame, element("p", 6, &[], json!([text("Top page")]))]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_canary_free(&projection);
        assert_eq!(projection.text, "Top page");
        assert!(projection.nodes.is_empty());
    }
}

/// The gateway must not have gained an `evaluate`-class capability by way of
/// the new observation methods. Absence, not denial.
#[test]
fn test_attack_observation_did_not_reintroduce_arbitrary_javascript() {
    let filter = CdpFilter::new();
    for method in [
        "Runtime.evaluate",
        "Runtime.callFunctionOn",
        "Runtime.compileScript",
        "Runtime.getProperties",
        "Runtime.awaitPromise",
        "DOM.getOuterHTML",
        "DOMSnapshot.captureSnapshot",
        "Accessibility.getFullAXTree",
        "DOM.getContentQuads",
        "DOM.resolveNode",
        "DOM.getFlattenedDocument",
        "Page.getResourceContent",
    ] {
        assert!(
            filter.validate_cdp_command(method, None).is_err(),
            "{method} must not be reachable"
        );
    }
}

/// Whole-page dumps must be denied at all times, not merely while a credential
/// is being injected. A page can echo a secret into the DOM at any moment, and
/// `page.snapshot_safe` is the only observation path that elides it.
#[test]
fn test_attack_whole_page_dumps_are_denied_outside_a_sensitive_window() {
    let filter = CdpFilter::new();
    assert!(!filter.has_sensitive_window());
    for method in [
        "DOMSnapshot.captureSnapshot",
        "DOMSnapshot.getSnapshot",
        "Accessibility.getFullAXTree",
        "Accessibility.getRootAXNode",
        "DOM.getOuterHTML",
        "DOM.getFlattenedDocument",
    ] {
        assert!(
            filter.validate_cdp_command(method, Some(1)).is_err(),
            "{method} must be denied with no sensitive window active"
        );
    }
}

/// Every CDP method the observation path needs must be explicitly allowlisted,
/// so that adding a feature cannot quietly widen the boundary.
#[test]
fn test_observation_uses_only_allowlisted_cdp_methods() {
    let filter = CdpFilter::new();
    for method in [
        "DOM.getDocument",
        "DOM.describeNode",
        "DOM.getBoxModel",
        "DOM.querySelectorAll",
        "Page.getNavigationHistory",
        "Page.navigateToHistoryEntry",
    ] {
        assert!(
            filter.validate_cdp_command(method, None).is_ok(),
            "{method} is required by the observation path"
        );
    }
}
