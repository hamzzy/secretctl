use chrono::Utc;
use secretctl_audit::{create_audit_event, AuditContext};
use secretctl_capability::{
    mint_capability, verify_and_consume_capability, CapabilityClaims, ExecutionContextSnapshot,
};
use secretctl_crypto::KeyPair;
use secretctl_domain::{
    ActionKind, ActionRequestState, AgentId, BrowserSession, BrowserSessionId,
    BrowserSessionState, Capability, CapabilityId, CredentialId,
    Execution, ExecutionId, ExecutionState, RecipeId, RequestId, SiteRecipe,
};
use secretctl_policy::PolicyEvaluator;
use secretctl_protocol::{
    ActionRequestParams, ActionResponseResult, ExecutorConsumeParams,
    ExecutorConsumeResult, ExecutorHeartbeatParams,
    ExecutorHeartbeatResult, ExecutorPrepareParams, ExecutorPrepareResult, ExecutorResultParams,
    ExecutorResultResult, ResolvedFieldInjection, RpcError, RpcErrorCode,
};
use secretctl_providers::SecretProvider;
use secretctl_store::SqliteStore;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub struct ActiveBrowserSession {
    pub session: BrowserSession,
    pub active_tab_count: u32,
}

pub struct CapabilityEntry {
    pub capability: Capability,
    pub token: String,
    pub claims: CapabilityClaims,
    pub recipe_id: RecipeId,
    pub credential_name: String,
}

pub struct ActiveExecution {
    pub execution: Execution,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub credential_id: CredentialId,
    pub action: ActionKind,
}

#[derive(Clone)]
pub struct BrokerState {
    pub broker_key: Arc<KeyPair>,
    pub key_id: String,
    pub store: SqliteStore,
    pub provider: Arc<dyn SecretProvider>,
    pub policy_evaluator: Arc<RwLock<PolicyEvaluator>>,
    pub sessions: Arc<RwLock<HashMap<BrowserSessionId, ActiveBrowserSession>>>,
    pub capabilities: Arc<Mutex<HashMap<CapabilityId, CapabilityEntry>>>,
    pub executions: Arc<Mutex<HashMap<ExecutionId, ActiveExecution>>>,
    pub recipes: Arc<RwLock<HashMap<RecipeId, SiteRecipe>>>,
    audit_sequence: Arc<AtomicU64>,
    latest_audit_hash: Arc<Mutex<Vec<u8>>>,
}

impl BrokerState {
    pub fn new(
        broker_key: KeyPair,
        key_id: impl Into<String>,
        store: SqliteStore,
        provider: Arc<dyn SecretProvider>,
        policy_evaluator: PolicyEvaluator,
    ) -> Self {
        let initial_hash = store
            .get_latest_audit_hash()
            .unwrap_or_else(|_| secretctl_audit::GENESIS_PREVIOUS_HASH.to_vec());

        Self {
            broker_key: Arc::new(broker_key),
            key_id: key_id.into(),
            store,
            provider,
            policy_evaluator: Arc::new(RwLock::new(policy_evaluator)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            capabilities: Arc::new(Mutex::new(HashMap::new())),
            executions: Arc::new(Mutex::new(HashMap::new())),
            recipes: Arc::new(RwLock::new(HashMap::new())),
            audit_sequence: Arc::new(AtomicU64::new(1)),
            latest_audit_hash: Arc::new(Mutex::new(initial_hash)),
        }
    }

    pub fn record_audit_event(
        &self,
        event_type: impl Into<String>,
        actor_type: impl Into<String>,
        actor_id: Option<String>,
        context: &AuditContext,
    ) -> Result<(), RpcError> {
        let seq = self.audit_sequence.fetch_add(1, Ordering::SeqCst);
        let mut prev_hash_lock = self.latest_audit_hash.lock().unwrap();

        let event = create_audit_event(
            seq,
            &prev_hash_lock,
            event_type,
            actor_type,
            actor_id,
            context,
            Utc::now(),
        )
        .map_err(|e| RpcError::new(RpcErrorCode::INTERNAL_ERROR, e.to_string()))?;

        self.store
            .insert_audit_event(&event)
            .map_err(|e| RpcError::new(RpcErrorCode::INTERNAL_ERROR, e.to_string()))?;

        *prev_hash_lock = event.event_hash.clone();
        Ok(())
    }

    pub fn register_recipe(&self, recipe: SiteRecipe) {
        let mut recipes = self.recipes.write().unwrap();
        recipes.insert(recipe.recipe_id.clone(), recipe);
    }

    pub fn register_browser_session(&self, session: BrowserSession) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(
            session.session_id.clone(),
            ActiveBrowserSession {
                session,
                active_tab_count: 1,
            },
        );
    }

    pub async fn handle_action_request(
        &self,
        agent_id: AgentId,
        params: ActionRequestParams,
    ) -> Result<ActionResponseResult, RpcError> {
        let now = Utc::now();
        let target_origin = &params.target.origin;
        let credential_id = CredentialId::new();

        // 1. Audit request
        let audit_ctx = AuditContext {
            request_id: Some(params.request_id.to_string()),
            credential_id: Some(params.identity.clone()),
            capability_id: None,
            browser_session_id: Some(params.browser_session_id.to_string()),
            target_origin: Some(target_origin.to_string()),
            action: Some(params.action.to_string()),
            decision: None,
            risk_level: None,
            error_code: None,
        };
        self.record_audit_event(
            "action.requested",
            "agent",
            Some(agent_id.to_string()),
            &audit_ctx,
        )?;

        // 2. Validate browser session exists and is active
        let assurance = {
            let sessions = self.sessions.read().unwrap();
            let active = sessions
                .get(&params.browser_session_id)
                .ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::SESSION_TERMINATED,
                        "Browser session not found or inactive",
                    )
                })?;
            if active.session.state != BrowserSessionState::Active {
                return Err(RpcError::new(
                    RpcErrorCode::SESSION_TERMINATED,
                    "Browser session is not active",
                ));
            }
            active.session.assurance.clone()
        };

        // 3. Evaluate Policy
        let decision = {
            let policy = self.policy_evaluator.read().unwrap();
            policy
                .evaluate(
                    &agent_id,
                    &params.identity,
                    params.action,
                    target_origin,
                    params.target.path_prefix.as_deref(),
                    &assurance,
                )
                .map_err(|e| {
                    let _ = self.record_audit_event(
                        "policy.evaluated",
                        "broker",
                        None,
                        &AuditContext {
                            request_id: Some(params.request_id.to_string()),
                            credential_id: Some(params.identity.clone()),
                            capability_id: None,
                            browser_session_id: Some(params.browser_session_id.to_string()),
                            target_origin: Some(target_origin.to_string()),
                            action: Some(params.action.to_string()),
                            decision: Some("deny".to_string()),
                            risk_level: None,
                            error_code: Some("AUTH_POLICY_DENIED".to_string()),
                        },
                    );
                    RpcError::new(RpcErrorCode::AUTH_POLICY_DENIED, e.to_string())
                })?
        };

        if decision.effect == secretctl_domain::PolicyEffect::Deny {
            return Err(RpcError::new(
                RpcErrorCode::AUTH_POLICY_DENIED,
                "Policy denied action",
            ));
        }

        // 4. Match site recipe
        let matched_recipe_id = {
            let recipes = self.recipes.read().unwrap();
            let mut found = None;
            for (id, recipe) in recipes.iter() {
                if recipe.action == params.action && recipe.top_origin.matches(target_origin) {
                    found = Some(id.clone());
                    break;
                }
            }
            found.unwrap_or_else(|| RecipeId::parse("rcp_default_login").unwrap_or_default())
        };

        // 5. Mint capability
        let (cap, token) = mint_capability(
            &self.broker_key,
            &self.key_id,
            params.request_id.clone(),
            agent_id.clone(),
            credential_id.clone(),
            params.action,
            target_origin.clone(),
            target_origin.clone(),
            params.browser_session_id.clone(),
            1, // Initial epoch
            now,
            decision.ttl_seconds,
            decision.max_uses,
        );

        let claims = secretctl_capability::parse_and_verify_token(
            &token,
            &self.broker_key.public_key_bytes(),
        )
        .map_err(|e| RpcError::new(RpcErrorCode::INTERNAL_ERROR, e.to_string()))?;

        // 6. Record capability in state
        {
            let mut caps = self.capabilities.lock().unwrap();
            caps.insert(
                cap.capability_id.clone(),
                CapabilityEntry {
                    capability: cap.clone(),
                    token: token.clone(),
                    claims,
                    recipe_id: matched_recipe_id,
                    credential_name: params.identity.clone(),
                },
            );
        }

        // 7. Audit capability minted
        self.record_audit_event(
            "capability.minted",
            "broker",
            None,
            &AuditContext {
                request_id: Some(params.request_id.to_string()),
                credential_id: Some(params.identity.clone()),
                capability_id: Some(cap.capability_id.to_string()),
                browser_session_id: Some(params.browser_session_id.to_string()),
                target_origin: Some(target_origin.to_string()),
                action: Some(params.action.to_string()),
                decision: Some("allow".to_string()),
                risk_level: Some(format!("{:?}", decision.risk_level).to_lowercase()),
                error_code: None,
            },
        )?;

        // Return Agent Response (Zero secrets!)
        Ok(ActionResponseResult {
            request_id: params.request_id,
            state: ActionRequestState::CapabilityIssued,
            result_code: Some("CAPABILITY_ISSUED".to_string()),
            execution_id: None,
            evidence_ref: Some(format!("cap:{}", cap.capability_id)),
            completed_at: None,
        })
    }

    pub async fn handle_executor_prepare(
        &self,
        params: ExecutorPrepareParams,
    ) -> Result<ExecutorPrepareResult, RpcError> {
        let recipes = self.recipes.read().unwrap();
        let mut matched = Vec::new();

        for (id, recipe) in recipes.iter() {
            if recipe.top_origin.matches(&params.context.top_origin) {
                matched.push(id.clone());
            }
        }

        Ok(ExecutorPrepareResult {
            prepared: true,
            challenge_nonce: uuid::Uuid::new_v4().to_string(),
            matching_recipes: matched,
        })
    }

    pub async fn handle_executor_consume(
        &self,
        params: ExecutorConsumeParams,
    ) -> Result<ExecutorConsumeResult, RpcError> {
        let now = Utc::now();
        let pub_key = self.broker_key.public_key_bytes();

        let context_snapshot = ExecutionContextSnapshot {
            top_origin: &params.current_context.top_origin,
            frame_origin: &params.current_context.frame_origin,
            browser_session_id: &params.current_context.browser_session_id,
            navigation_epoch: params.current_context.navigation_epoch,
        };

        // Atomic capability lock and consumption
        let (claims, recipe_id, credential_name) = {
            let mut caps = self.capabilities.lock().unwrap();

            // Find matching capability entry
            let entry = caps
                .values_mut()
                .find(|e| e.token == params.capability_token)
                .ok_or_else(|| {
                    RpcError::new(RpcErrorCode::CAPABILITY_CONSUMED, "Invalid or unknown capability token")
                })?;

            // Perform single-use atomic consumption check
            let claims = verify_and_consume_capability(
                &mut entry.capability,
                &params.capability_token,
                &pub_key,
                &context_snapshot,
                now,
            )
            .map_err(|e| match e {
                secretctl_capability::CapabilityError::Expired(_) => {
                    RpcError::new(RpcErrorCode::CAPABILITY_EXPIRED, "Capability expired")
                }
                secretctl_capability::CapabilityError::AlreadyConsumed { .. } => {
                    RpcError::new(RpcErrorCode::CAPABILITY_CONSUMED, "Capability already consumed")
                }
                secretctl_capability::CapabilityError::EpochMismatch { .. } => {
                    RpcError::new(RpcErrorCode::EPOCH_INVALIDATED, "Epoch mismatch")
                }
                secretctl_capability::CapabilityError::BindingMismatch { .. } => {
                    RpcError::new(RpcErrorCode::ORIGIN_MISMATCH, "Context binding mismatch")
                }
                _ => RpcError::new(RpcErrorCode::SECURITY_VIOLATION, e.to_string()),
            })?;

            (claims, entry.recipe_id.clone(), entry.credential_name.clone())
        };

        // Audit capability consumed
        self.record_audit_event(
            "capability.consumed",
            "executor",
            None,
            &AuditContext {
                request_id: Some(claims.req_id.to_string()),
                credential_id: Some(claims.cred_id.to_string()),
                capability_id: Some(claims.jti.to_string()),
                browser_session_id: Some(claims.browser_session_id.to_string()),
                target_origin: Some(claims.top_origin.to_string()),
                action: Some(claims.action.to_string()),
                decision: None,
                risk_level: None,
                error_code: None,
            },
        )?;

        // Retrieve secret bytes or compute TOTP based on action kind
        let fields = match claims.action {
            ActionKind::AuthenticateTotp => {
                let seed_bytes = self
                    .provider
                    .get_secret(&credential_name)
                    .await
                    .map_err(|e| {
                        RpcError::new(
                            RpcErrorCode::INTERNAL_ERROR,
                            format!("Failed to retrieve TOTP seed: {}", e),
                        )
                    })?;

                let generator = secretctl_crypto::TotpGenerator::new();
                let (totp_code, _time_step) = generator
                    .generate(seed_bytes.as_bytes(), now.timestamp() as u64)
                    .map_err(|_| {
                        RpcError::new(
                            RpcErrorCode::CAPABILITY_EXPIRED,
                            "TOTP time step expired or margin too close",
                        )
                    })?;

                vec![ResolvedFieldInjection {
                    role: "totp_code".to_string(),
                    selector: "input[autocomplete='one-time-code'], input[name='otp'], input[type='tel']".to_string(),
                    optional: false,
                    clear_first: true,
                    encrypted_value: totp_code,
                }]
            }
            ActionKind::FormSensitiveFill => {
                let secret_bytes = self
                    .provider
                    .get_secret(&credential_name)
                    .await
                    .map_err(|e| {
                        RpcError::new(
                            RpcErrorCode::INTERNAL_ERROR,
                            format!("Failed to retrieve sensitive form fields: {}", e),
                        )
                    })?;

                vec![ResolvedFieldInjection {
                    role: "sensitive_text".to_string(),
                    selector: "input[name='sensitive_value'], textarea".to_string(),
                    optional: false,
                    clear_first: true,
                    encrypted_value: String::from_utf8_lossy(secret_bytes.as_bytes()).to_string(),
                }]
            }
            _ => {
                let secret_bytes = self
                    .provider
                    .get_secret(&credential_name)
                    .await
                    .map_err(|e| {
                        RpcError::new(
                            RpcErrorCode::INTERNAL_ERROR,
                            format!("Failed to retrieve secret: {}", e),
                        )
                    })?;

                vec![ResolvedFieldInjection {
                    role: "password".to_string(),
                    selector: "input[type=password]".to_string(),
                    optional: false,
                    clear_first: true,
                    encrypted_value: String::from_utf8_lossy(secret_bytes.as_bytes()).to_string(),
                }]
            }
        };

        // Audit secret accessed
        self.record_audit_event(
            "secret.accessed",
            "broker",
            None,
            &AuditContext {
                request_id: Some(claims.req_id.to_string()),
                credential_id: Some(credential_name),
                capability_id: Some(claims.jti.to_string()),
                browser_session_id: Some(claims.browser_session_id.to_string()),
                target_origin: Some(claims.top_origin.to_string()),
                action: Some(claims.action.to_string()),
                decision: None,
                risk_level: None,
                error_code: None,
            },
        )?;

        let execution_id = ExecutionId::new();

        // Create execution entry
        {
            let mut execs = self.executions.lock().unwrap();
            execs.insert(
                execution_id.clone(),
                ActiveExecution {
                    execution: Execution {
                        execution_id: execution_id.clone(),
                        capability_id: claims.jti.clone(),
                        state: ExecutionState::Consuming,
                        prepared_context_digest: None,
                        started_at: Some(now),
                        completed_at: None,
                        result_code: None,
                    },
                    request_id: claims.req_id,
                    agent_id: claims.agent_id,
                    credential_id: claims.cred_id,
                    action: claims.action,
                },
            );
        }

        Ok(ExecutorConsumeResult {
            execution_id,
            recipe_id,
            fields,
            auto_submit_selector: Some("button[type=submit]".to_string()),
        })
    }

    pub async fn handle_executor_result(
        &self,
        params: ExecutorResultParams,
    ) -> Result<ExecutorResultResult, RpcError> {
        let (req_id, cap_id, cred_id, act) = {
            let mut execs = self.executions.lock().unwrap();
            let active = execs
                .get_mut(&params.execution_id)
                .ok_or_else(|| RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown execution ID"))?;

            active.execution.state = if params.status == "completed" {
                ExecutionState::Completed
            } else {
                ExecutionState::Failed
            };
            active.execution.completed_at = Some(Utc::now());
            active.execution.result_code = Some(params.result_code.clone());

            (
                active.request_id.clone(),
                active.execution.capability_id.clone(),
                active.credential_id.clone(),
                active.action,
            )
        };

        // Audit execution completion
        self.record_audit_event(
            if params.status == "completed" {
                "executor.completed"
            } else {
                "executor.failed"
            },
            "executor",
            None,
            &AuditContext {
                request_id: Some(req_id.to_string()),
                credential_id: Some(cred_id.to_string()),
                capability_id: Some(cap_id.to_string()),
                browser_session_id: None,
                target_origin: None,
                action: Some(act.to_string()),
                decision: None,
                risk_level: None,
                error_code: if params.status == "failed" {
                    Some(params.result_code)
                } else {
                    None
                },
            },
        )?;

        Ok(ExecutorResultResult { acknowledged: true })
    }

    pub async fn handle_executor_heartbeat(
        &self,
        params: ExecutorHeartbeatParams,
    ) -> Result<ExecutorHeartbeatResult, RpcError> {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(session_entry) = sessions.get_mut(&params.browser_session_id) {
            session_entry.session.last_heartbeat_at = Utc::now();
            session_entry.active_tab_count = params.active_tab_count;
            session_entry.session.state = BrowserSessionState::Active;
        }
        Ok(ExecutorHeartbeatResult { acknowledged: true })
    }
}
