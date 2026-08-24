use chrono::Utc;
use secretctl_audit::{AuditContext, create_audit_event};
use secretctl_capability::{
    CapabilityClaims, ExecutionContextSnapshot, mint_capability, verify_and_consume_capability,
};
use secretctl_crypto::{KeyPair, SecretBytes};
use secretctl_domain::{
    ActionKind, ActionRequestState, AgentId, Approval, ApprovalId, BrowserSession,
    BrowserSessionId, BrowserSessionState, Capability, CapabilityId, CredentialDescriptor,
    CredentialId, Execution, ExecutionId, ExecutionState, PageContext, PolicyDecision, RecipeId,
    RequestId, SiteRecipe,
};
use secretctl_policy::PolicyEvaluator;
use secretctl_protocol::{
    ActionCancelParams, ActionCancelResult, ActionRequestParams, ActionResponseResult,
    ActionStatusParams, ActionStatusResult, ExecutorConsumeParams, ExecutorConsumeResult,
    ExecutorHeartbeatParams, ExecutorHeartbeatResult, ExecutorPrepareParams, ExecutorPrepareResult,
    ExecutorResultParams, ExecutorResultResult, ResolvedFieldInjection, RpcError, RpcErrorCode,
};
use secretctl_providers::SecretProvider;
use secretctl_store::SqliteStore;
use std::collections::HashMap;
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
    pub provider_locator: String,
}

pub struct ActiveExecution {
    pub execution: Execution,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub credential_id: CredentialId,
    pub action: ActionKind,
}

#[derive(Clone)]
pub struct AuthorizationContext {
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub identity_name: String,
    pub credential: CredentialDescriptor,
    pub action: ActionKind,
    pub browser_session_id: BrowserSessionId,
    pub extension_key_id: String,
    pub page_context: PageContext,
    pub recipe: SiteRecipe,
    pub decision: PolicyDecision,
}

#[derive(Clone)]
pub struct PendingApprovalEntry {
    pub approval: Approval,
    pub authorization: AuthorizationContext,
}

struct AuditCursor {
    next_sequence: u64,
    latest_hash: Vec<u8>,
}

#[derive(Clone)]
pub struct BrokerState {
    pub broker_key: Arc<KeyPair>,
    pub key_id: String,
    pub store: SqliteStore,
    pub provider: Arc<dyn SecretProvider>,
    pub policy_evaluator: Arc<RwLock<PolicyEvaluator>>,
    pub sessions: Arc<RwLock<HashMap<BrowserSessionId, ActiveBrowserSession>>>,
    pub page_contexts: Arc<RwLock<HashMap<BrowserSessionId, HashMap<u32, PageContext>>>>,
    pub capabilities: Arc<Mutex<HashMap<CapabilityId, CapabilityEntry>>>,
    pub executions: Arc<Mutex<HashMap<ExecutionId, ActiveExecution>>>,
    pub requests: Arc<RwLock<HashMap<RequestId, ActionResponseResult>>>,
    pub request_agents: Arc<RwLock<HashMap<RequestId, AgentId>>>,
    pub request_fingerprints: Arc<Mutex<HashMap<RequestId, [u8; 32]>>>,
    pub approvals: Arc<Mutex<HashMap<ApprovalId, PendingApprovalEntry>>>,
    pub recipes: Arc<RwLock<HashMap<RecipeId, SiteRecipe>>>,
    audit_key_version: u32,
    audit_key: Arc<SecretBytes>,
    audit_cursor: Arc<Mutex<AuditCursor>>,
}

impl BrokerState {
    pub fn new(
        broker_key: KeyPair,
        key_id: impl Into<String>,
        store: SqliteStore,
        provider: Arc<dyn SecretProvider>,
        policy_evaluator: PolicyEvaluator,
    ) -> Self {
        let fallback_audit_key =
            SecretBytes::new(secretctl_crypto::sha256_digest(&broker_key.to_bytes()).to_vec());
        Self::new_with_audit_key(
            broker_key,
            key_id,
            fallback_audit_key,
            1,
            store,
            provider,
            policy_evaluator,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_audit_key(
        broker_key: KeyPair,
        key_id: impl Into<String>,
        audit_key: SecretBytes,
        audit_key_version: u32,
        store: SqliteStore,
        provider: Arc<dyn SecretProvider>,
        policy_evaluator: PolicyEvaluator,
    ) -> Self {
        let initial_hash = store
            .get_latest_audit_hash()
            .unwrap_or_else(|_| secretctl_audit::GENESIS_PREVIOUS_HASH.to_vec());
        let initial_sequence = store.get_latest_audit_sequence().unwrap_or(0) + 1;
        let _ = store.recover_incomplete_state();

        Self {
            broker_key: Arc::new(broker_key),
            key_id: key_id.into(),
            store,
            provider,
            policy_evaluator: Arc::new(RwLock::new(policy_evaluator)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            page_contexts: Arc::new(RwLock::new(HashMap::new())),
            capabilities: Arc::new(Mutex::new(HashMap::new())),
            executions: Arc::new(Mutex::new(HashMap::new())),
            requests: Arc::new(RwLock::new(HashMap::new())),
            request_agents: Arc::new(RwLock::new(HashMap::new())),
            request_fingerprints: Arc::new(Mutex::new(HashMap::new())),
            approvals: Arc::new(Mutex::new(HashMap::new())),
            recipes: Arc::new(RwLock::new(HashMap::new())),
            audit_key_version,
            audit_key: Arc::new(audit_key),
            audit_cursor: Arc::new(Mutex::new(AuditCursor {
                next_sequence: initial_sequence,
                latest_hash: initial_hash,
            })),
        }
    }

    pub fn record_audit_event(
        &self,
        event_type: impl Into<String>,
        actor_type: impl Into<String>,
        actor_id: Option<String>,
        context: &AuditContext,
    ) -> Result<(), RpcError> {
        let mut cursor = self.audit_cursor.lock().unwrap();

        let event = create_audit_event(
            cursor.next_sequence,
            &cursor.latest_hash,
            self.audit_key_version,
            self.audit_key.as_bytes(),
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

        cursor.next_sequence += 1;
        cursor.latest_hash = event.event_hash;
        Ok(())
    }

    pub fn write_audit_checkpoint(&self) -> Result<(), RpcError> {
        self.record_audit_event(
            "audit.checkpoint",
            "broker",
            None,
            &AuditContext {
                request_id: None,
                credential_id: None,
                capability_id: None,
                browser_session_id: None,
                target_origin: None,
                action: None,
                decision: Some("shutdown".to_string()),
                risk_level: None,
                error_code: None,
            },
        )?;
        let cursor = self.audit_cursor.lock().unwrap();
        let checkpoint = secretctl_audit::create_audit_checkpoint(
            cursor.next_sequence - 1,
            cursor.latest_hash.clone(),
            self.audit_key_version,
            self.key_id.clone(),
            &self.broker_key,
            Utc::now(),
        );
        self.store
            .insert_audit_checkpoint(&checkpoint)
            .map_err(|_| RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Checkpoint unavailable"))
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

    pub fn register_page_context(&self, context: PageContext, session_id: BrowserSessionId) {
        let mut contexts = self.page_contexts.write().unwrap();
        contexts
            .entry(session_id)
            .or_default()
            .insert(context.tab_id, context);
    }

    fn approval_context_digest(authorization: &AuthorizationContext) -> Vec<u8> {
        let epoch = authorization.page_context.navigation_epoch.to_be_bytes();
        let tab_id = authorization.page_context.tab_id.to_be_bytes();
        let frame_id = authorization.page_context.frame_id.to_be_bytes();
        secretctl_crypto::compute_context_digest(&[
            authorization.agent_id.as_str().as_bytes(),
            authorization.credential.credential_id.as_str().as_bytes(),
            authorization.action.as_str().as_bytes(),
            authorization.page_context.top_origin.as_str().as_bytes(),
            authorization.page_context.frame_origin.as_str().as_bytes(),
            authorization.browser_session_id.as_str().as_bytes(),
            authorization.extension_key_id.as_bytes(),
            &tab_id,
            &frame_id,
            authorization.page_context.document_id.as_bytes(),
            &epoch,
            &authorization.recipe.content_hash,
            &authorization.decision.policy_hash,
        ])
        .to_vec()
    }

    fn mint_authorized_capability(
        &self,
        authorization: AuthorizationContext,
        approval_id: Option<ApprovalId>,
    ) -> Result<ActionResponseResult, RpcError> {
        let now = Utc::now();
        let (capability, token) = mint_capability(
            &self.broker_key,
            &self.key_id,
            authorization.request_id.clone(),
            authorization.agent_id,
            authorization.credential.credential_id.clone(),
            authorization.action,
            authorization.page_context.top_origin.clone(),
            authorization.page_context.frame_origin.clone(),
            authorization.browser_session_id.clone(),
            authorization.extension_key_id,
            authorization.page_context.tab_id,
            authorization.page_context.frame_id,
            authorization.page_context.document_id,
            authorization.page_context.navigation_epoch,
            authorization.recipe.recipe_id.clone(),
            authorization.recipe.content_hash,
            authorization.decision.policy_hash.clone(),
            now,
            authorization.decision.ttl_seconds,
            authorization.decision.max_uses,
        );
        let claims = secretctl_capability::parse_and_verify_token(
            &token,
            &self.broker_key.public_key_bytes(),
        )
        .map_err(|_| RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Capability mint failed"))?;
        let audit_context = AuditContext {
            request_id: Some(authorization.request_id.to_string()),
            credential_id: Some(authorization.credential.credential_id.to_string()),
            capability_id: Some(capability.capability_id.to_string()),
            browser_session_id: Some(authorization.browser_session_id.to_string()),
            target_origin: Some(capability.top_origin.to_string()),
            action: Some(authorization.action.to_string()),
            decision: Some(if approval_id.is_some() {
                "user_approved".to_string()
            } else {
                "auto_approved".to_string()
            }),
            risk_level: Some(format!("{:?}", authorization.decision.risk_level).to_lowercase()),
            error_code: None,
        };
        {
            let mut cursor = self.audit_cursor.lock().unwrap();
            let audit_event = create_audit_event(
                cursor.next_sequence,
                &cursor.latest_hash,
                self.audit_key_version,
                self.audit_key.as_bytes(),
                "capability.minted",
                "broker",
                None,
                &audit_context,
                Utc::now(),
            )
            .map_err(|_| RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Audit unavailable"))?;
            self.store
                .insert_capability_with_audit(&capability, &self.key_id, &audit_event)
                .map_err(|_| {
                    RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Durable state unavailable")
                })?;
            cursor.next_sequence += 1;
            cursor.latest_hash = audit_event.event_hash;
        }
        self.capabilities.lock().unwrap().insert(
            capability.capability_id.clone(),
            CapabilityEntry {
                capability: capability.clone(),
                token,
                claims,
                recipe_id: authorization.recipe.recipe_id,
                provider_locator: authorization.credential.provider_locator,
            },
        );
        let response = ActionResponseResult {
            request_id: authorization.request_id,
            state: ActionRequestState::CapabilityIssued,
            result_code: Some("CAPABILITY_ISSUED".to_string()),
            execution_id: None,
            evidence_ref: Some(format!("cap:{}", capability.capability_id)),
            completed_at: None,
        };
        self.requests
            .write()
            .unwrap()
            .insert(response.request_id.clone(), response.clone());
        Ok(response)
    }

    pub async fn handle_action_request(
        &self,
        agent_id: AgentId,
        params: ActionRequestParams,
    ) -> Result<ActionResponseResult, RpcError> {
        if params.reason.chars().count() > 500
            || params.timeout_ms == 0
            || params.timeout_ms > 60_000
        {
            return Err(RpcError::new(
                RpcErrorCode::INVALID_PARAMS,
                "Action reason or timeout is outside allowed limits",
            ));
        }
        let encoded = serde_json::to_vec(&params).map_err(|_| {
            RpcError::new(
                RpcErrorCode::INVALID_PARAMS,
                "Action request is not serializable",
            )
        })?;
        let fingerprint = secretctl_crypto::sha256_digest(&encoded);
        {
            let mut fingerprints = self.request_fingerprints.lock().unwrap();
            if let Some(existing) = fingerprints.get(&params.request_id) {
                if existing != &fingerprint
                    || self.request_agents.read().unwrap().get(&params.request_id)
                        != Some(&agent_id)
                {
                    return Err(RpcError::new(
                        RpcErrorCode::INVALID_PARAMS,
                        "request_id_conflict",
                    ));
                }
                return self
                    .requests
                    .read()
                    .unwrap()
                    .get(&params.request_id)
                    .cloned()
                    .ok_or_else(|| {
                        RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Request state unavailable")
                    });
            }
            fingerprints.insert(params.request_id.clone(), fingerprint);
        }

        self.request_agents
            .write()
            .unwrap()
            .insert(params.request_id.clone(), agent_id.clone());
        self.requests.write().unwrap().insert(
            params.request_id.clone(),
            ActionResponseResult {
                request_id: params.request_id.clone(),
                state: ActionRequestState::Requested,
                result_code: Some("REQUESTED".to_string()),
                execution_id: None,
                evidence_ref: None,
                completed_at: None,
            },
        );

        let result = self
            .handle_new_action_request(agent_id, params.clone())
            .await;
        if let Err(error) = &result {
            if let Some(request) = self.requests.write().unwrap().get_mut(&params.request_id) {
                request.state = ActionRequestState::Failed;
                request.result_code = Some(error.message.clone());
                request.completed_at = Some(Utc::now().to_rfc3339());
            }
        }
        result
    }

    async fn handle_new_action_request(
        &self,
        agent_id: AgentId,
        params: ActionRequestParams,
    ) -> Result<ActionResponseResult, RpcError> {
        let now = Utc::now();
        let target_origin = &params.target.origin;
        if target_origin.scheme() == "http"
            && !matches!(target_origin.host(), "localhost" | "127.0.0.1" | "::1")
        {
            return Err(RpcError::new(
                RpcErrorCode::ORIGIN_MISMATCH,
                "Insecure non-loopback origins are denied",
            ));
        }
        let credential = self
            .store
            .get_credential_by_name(&params.identity)
            .map_err(|_| {
                RpcError::new(RpcErrorCode::AUTH_POLICY_DENIED, "Identity is unavailable")
            })?;
        if credential.disabled_at.is_some()
            || !credential.allowed_actions.contains(&params.action)
            || credential.provider != self.provider.provider_name()
        {
            return Err(RpcError::new(
                RpcErrorCode::AUTH_POLICY_DENIED,
                "Identity is not permitted for this action",
            ));
        }
        let credential_id = credential.credential_id.clone();

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
        let (assurance, extension_key_id) = {
            let sessions = self.sessions.read().unwrap();
            let active = sessions.get(&params.browser_session_id).ok_or_else(|| {
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
            if now - active.session.last_heartbeat_at > chrono::Duration::seconds(10) {
                return Err(RpcError::new(
                    RpcErrorCode::SESSION_TERMINATED,
                    "Browser session heartbeat is stale",
                ));
            }
            (
                active.session.assurance.clone(),
                active.session.extension_key_id.clone(),
            )
        };

        // Agent-supplied target and tab values are only hints. Authority comes from
        // the most recent context reported by the trusted browser runtime.
        let measured_context = {
            let contexts = self.page_contexts.read().unwrap();
            let session_contexts = contexts.get(&params.browser_session_id).ok_or_else(|| {
                RpcError::new(
                    RpcErrorCode::ORIGIN_MISMATCH,
                    "Verified page context unavailable",
                )
            })?;
            let context = params
                .tab_hint
                .and_then(|tab_id| session_contexts.get(&tab_id))
                .or_else(|| {
                    if session_contexts.len() == 1 {
                        session_contexts.values().next()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::ORIGIN_MISMATCH,
                        "Verified tab context unavailable",
                    )
                })?;
            if now - context.observed_at > chrono::Duration::seconds(2) {
                return Err(RpcError::new(
                    RpcErrorCode::ORIGIN_MISMATCH,
                    "Verified page context is stale",
                ));
            }
            if !context.top_origin.matches(target_origin) {
                return Err(RpcError::new(
                    RpcErrorCode::ORIGIN_MISMATCH,
                    "Requested origin does not match verified browser origin",
                ));
            }
            if params
                .target
                .path_prefix
                .as_ref()
                .is_some_and(|prefix| !context.path.starts_with(prefix))
            {
                return Err(RpcError::new(
                    RpcErrorCode::ORIGIN_MISMATCH,
                    "Requested path constraint does not match verified browser path",
                ));
            }
            context.clone()
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
                    Some(&measured_context.path),
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
        let matched_recipe = {
            let recipes = self.recipes.read().unwrap();
            recipes
                .values()
                .find(|recipe| {
                    recipe.enabled
                        && recipe.action == params.action
                        && recipe
                            .match_rule
                            .top_origin
                            .matches(&measured_context.top_origin)
                        && recipe
                            .match_rule
                            .frame_origin
                            .as_ref()
                            .is_none_or(|origin| origin.matches(&measured_context.frame_origin))
                        && recipe
                            .match_rule
                            .path_prefix
                            .as_ref()
                            .is_none_or(|prefix| measured_context.path.starts_with(prefix))
                })
                .cloned()
                .ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::RECIPE_NOT_FOUND,
                        "No enabled recipe matches verified context",
                    )
                })?
        };

        let authorization = AuthorizationContext {
            request_id: params.request_id.clone(),
            agent_id,
            identity_name: params.identity,
            credential,
            action: params.action,
            browser_session_id: params.browser_session_id,
            extension_key_id,
            page_context: measured_context,
            recipe: matched_recipe,
            decision,
        };

        if authorization.decision.require_user_presence {
            let approval_id = ApprovalId::new();
            let context_digest = Self::approval_context_digest(&authorization);
            let approval = Approval {
                approval_id: approval_id.clone(),
                request_id: authorization.request_id.clone(),
                decision: "pending".to_string(),
                actor: None,
                presence: None,
                context_digest,
                decided_at: None,
                expires_at: now + chrono::Duration::seconds(60),
            };
            let approval_context = AuditContext {
                request_id: Some(authorization.request_id.to_string()),
                credential_id: Some(credential_id.to_string()),
                capability_id: None,
                browser_session_id: Some(authorization.browser_session_id.to_string()),
                target_origin: Some(authorization.page_context.top_origin.to_string()),
                action: Some(authorization.action.to_string()),
                decision: Some("pending".to_string()),
                risk_level: Some(format!("{:?}", authorization.decision.risk_level).to_lowercase()),
                error_code: None,
            };
            {
                let mut cursor = self.audit_cursor.lock().unwrap();
                let audit_event = create_audit_event(
                    cursor.next_sequence,
                    &cursor.latest_hash,
                    self.audit_key_version,
                    self.audit_key.as_bytes(),
                    "approval.requested",
                    "broker",
                    None,
                    &approval_context,
                    Utc::now(),
                )
                .map_err(|_| RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Audit unavailable"))?;
                self.store
                    .insert_approval_with_audit(&approval, &audit_event)
                    .map_err(|_| {
                        RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Approval storage unavailable")
                    })?;
                cursor.next_sequence += 1;
                cursor.latest_hash = audit_event.event_hash;
            }
            self.approvals.lock().unwrap().insert(
                approval_id.clone(),
                PendingApprovalEntry {
                    approval,
                    authorization: authorization.clone(),
                },
            );
            let response = ActionResponseResult {
                request_id: authorization.request_id,
                state: ActionRequestState::AwaitingApproval,
                result_code: Some("APPROVAL_REQUIRED".to_string()),
                execution_id: None,
                evidence_ref: Some(format!("approval:{approval_id}")),
                completed_at: None,
            };
            self.requests
                .write()
                .unwrap()
                .insert(response.request_id.clone(), response.clone());
            Ok(response)
        } else {
            self.mint_authorized_capability(authorization, None)
        }
    }

    pub fn handle_action_status(
        &self,
        agent_id: &AgentId,
        params: ActionStatusParams,
    ) -> Result<ActionStatusResult, RpcError> {
        if self.request_agents.read().unwrap().get(&params.request_id) != Some(agent_id) {
            return Err(RpcError::new(
                RpcErrorCode::INVALID_PARAMS,
                "Unknown request ID",
            ));
        }
        let requests = self.requests.read().unwrap();
        let request = requests
            .get(&params.request_id)
            .ok_or_else(|| RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown request ID"))?;
        Ok(ActionStatusResult {
            request_id: request.request_id.clone(),
            state: request.state,
            detail: request.result_code.clone(),
        })
    }

    pub fn handle_action_cancel(
        &self,
        agent_id: &AgentId,
        params: ActionCancelParams,
    ) -> Result<ActionCancelResult, RpcError> {
        if self.request_agents.read().unwrap().get(&params.request_id) != Some(agent_id) {
            return Err(RpcError::new(
                RpcErrorCode::INVALID_PARAMS,
                "Unknown request ID",
            ));
        }
        let mut requests = self.requests.write().unwrap();
        let request = requests
            .get_mut(&params.request_id)
            .ok_or_else(|| RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown request ID"))?;
        if request.state.is_terminal() || request.state == ActionRequestState::Executing {
            return Ok(ActionCancelResult {
                request_id: params.request_id,
                cancelled: false,
            });
        }
        request.state = ActionRequestState::Cancelled;
        request.result_code = Some("CANCELLED".to_string());
        let mut capabilities = self.capabilities.lock().unwrap();
        for entry in capabilities.values_mut() {
            if entry.capability.request_id == params.request_id
                && !entry.capability.state.is_terminal()
            {
                entry.capability.state = secretctl_domain::CapabilityState::Revoked;
                entry.capability.revoked_reason = Some("request_cancelled".to_string());
            }
        }
        Ok(ActionCancelResult {
            request_id: params.request_id,
            cancelled: true,
        })
    }

    pub fn list_pending_approvals(&self) -> Vec<Approval> {
        self.approvals
            .lock()
            .unwrap()
            .values()
            .filter(|entry| entry.approval.decision == "pending")
            .map(|entry| entry.approval.clone())
            .collect()
    }

    pub fn expire_pending_approvals(&self, now: chrono::DateTime<Utc>) -> Result<usize, RpcError> {
        let expired = self
            .approvals
            .lock()
            .unwrap()
            .values()
            .filter(|entry| entry.approval.expires_at <= now)
            .map(|entry| {
                (
                    entry.approval.approval_id.clone(),
                    entry.approval.context_digest.clone(),
                )
            })
            .collect::<Vec<_>>();
        for (approval_id, context_digest) in &expired {
            self.decide_approval(approval_id, false, context_digest, "broker-timeout", false)?;
        }
        Ok(expired.len())
    }

    pub fn decide_approval(
        &self,
        approval_id: &ApprovalId,
        approve: bool,
        context_digest: &[u8],
        actor: &str,
        presence_verified: bool,
    ) -> Result<ActionResponseResult, RpcError> {
        let mut pending = self
            .approvals
            .lock()
            .unwrap()
            .get(approval_id)
            .cloned()
            .ok_or_else(|| RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown approval ID"))?;
        let now = Utc::now();
        let latest_context = self
            .page_contexts
            .read()
            .unwrap()
            .get(&pending.authorization.browser_session_id)
            .and_then(|contexts| contexts.get(&pending.authorization.page_context.tab_id))
            .cloned();
        let context_is_current = latest_context.is_some_and(|current| {
            current.document_id == pending.authorization.page_context.document_id
                && current.navigation_epoch == pending.authorization.page_context.navigation_epoch
                && current.top_origin == pending.authorization.page_context.top_origin
                && current.frame_origin == pending.authorization.page_context.frame_origin
                && now - current.observed_at <= chrono::Duration::seconds(2)
        });

        let outcome = if now >= pending.approval.expires_at {
            "expired"
        } else if context_digest != pending.approval.context_digest || !context_is_current {
            "invalidated"
        } else if !approve
            || (pending.authorization.decision.require_user_presence && !presence_verified)
        {
            "denied"
        } else {
            "approved"
        };
        pending.approval.decision = outcome.to_string();
        pending.approval.actor = Some(actor.to_string());
        pending.approval.presence = Some(if presence_verified {
            "verified".to_string()
        } else {
            "absent".to_string()
        });
        pending.approval.decided_at = Some(now);
        let decision_context = AuditContext {
            request_id: Some(pending.authorization.request_id.to_string()),
            credential_id: Some(pending.authorization.credential.credential_id.to_string()),
            capability_id: None,
            browser_session_id: Some(pending.authorization.browser_session_id.to_string()),
            target_origin: Some(pending.authorization.page_context.top_origin.to_string()),
            action: Some(pending.authorization.action.to_string()),
            decision: Some(outcome.to_string()),
            risk_level: Some(
                format!("{:?}", pending.authorization.decision.risk_level).to_lowercase(),
            ),
            error_code: (outcome != "approved").then(|| "APPROVAL_REJECTED".to_string()),
        };
        {
            let mut cursor = self.audit_cursor.lock().unwrap();
            let audit_event = create_audit_event(
                cursor.next_sequence,
                &cursor.latest_hash,
                self.audit_key_version,
                self.audit_key.as_bytes(),
                match outcome {
                    "approved" => "approval.approved",
                    "denied" => "approval.denied",
                    "expired" => "approval.expired",
                    _ => "approval.invalidated",
                },
                "user",
                Some(actor.to_string()),
                &decision_context,
                Utc::now(),
            )
            .map_err(|_| RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Audit unavailable"))?;
            self.store
                .update_approval_with_audit(&pending.approval, &audit_event)
                .map_err(|_| {
                    RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Approval storage unavailable")
                })?;
            cursor.next_sequence += 1;
            cursor.latest_hash = audit_event.event_hash;
        }
        self.approvals.lock().unwrap().remove(approval_id);

        if outcome == "approved" {
            return self
                .mint_authorized_capability(pending.authorization, Some(approval_id.clone()));
        }

        let state = if outcome == "expired" {
            ActionRequestState::Expired
        } else {
            ActionRequestState::Denied
        };
        let response = ActionResponseResult {
            request_id: pending.authorization.request_id,
            state,
            result_code: Some(outcome.to_ascii_uppercase()),
            execution_id: None,
            evidence_ref: None,
            completed_at: Some(now.to_rfc3339()),
        };
        self.requests
            .write()
            .unwrap()
            .insert(response.request_id.clone(), response.clone());
        Ok(response)
    }

    pub async fn handle_executor_prepare(
        &self,
        params: ExecutorPrepareParams,
    ) -> Result<ExecutorPrepareResult, RpcError> {
        let page_context = PageContext {
            tab_id: params.context.tab_id,
            frame_id: params.context.frame_id,
            top_origin: params.context.top_origin.clone(),
            frame_origin: params.context.frame_origin.clone(),
            navigation_epoch: params.context.navigation_epoch,
            document_id: params.context.document_id.clone(),
            path: params.context.path.clone(),
            path_sha256: params.context.path_sha256.clone(),
            tls: params.context.tls,
            incognito: params.context.incognito,
            observed_at: Utc::now(),
        };
        self.register_page_context(page_context, params.context.browser_session_id.clone());

        let recipes = self.recipes.read().unwrap();
        let mut matched = Vec::new();

        for (id, recipe) in recipes.iter() {
            if recipe
                .match_rule
                .top_origin
                .matches(&params.context.top_origin)
                && recipe
                    .match_rule
                    .frame_origin
                    .as_ref()
                    .is_none_or(|origin| origin.matches(&params.context.frame_origin))
                && recipe
                    .match_rule
                    .path_prefix
                    .as_ref()
                    .is_none_or(|prefix| params.context.path.starts_with(prefix))
            {
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
        let mut now = Utc::now();
        let totp_wait = {
            let caps = self.capabilities.lock().unwrap();
            caps.values()
                .find(|entry| entry.token == params.capability_token)
                .filter(|entry| entry.capability.action == ActionKind::AuthenticateTotp)
                .and_then(|_| {
                    let generator = secretctl_crypto::TotpGenerator::new();
                    let (_, seconds_remaining) =
                        generator.compute_time_step(now.timestamp() as u64);
                    (seconds_remaining < 2).then_some(seconds_remaining)
                })
        };
        if let Some(seconds) = totp_wait {
            // Cross the boundary before atomically consuming the capability so
            // a near-expiry code is never handed to the executor.
            tokio::time::sleep(std::time::Duration::from_millis(seconds * 1_000 + 50)).await;
            now = Utc::now();
        }
        let pub_key = self.broker_key.public_key_bytes();
        let extension_key_id = {
            let sessions = self.sessions.read().unwrap();
            sessions
                .get(&params.current_context.browser_session_id)
                .ok_or_else(|| {
                    RpcError::new(RpcErrorCode::SESSION_TERMINATED, "Unknown browser session")
                })?
                .session
                .extension_key_id
                .clone()
        };

        let context_snapshot = ExecutionContextSnapshot {
            top_origin: &params.current_context.top_origin,
            frame_origin: &params.current_context.frame_origin,
            browser_session_id: &params.current_context.browser_session_id,
            extension_key_id: &extension_key_id,
            tab_id: params.current_context.tab_id,
            frame_id: params.current_context.frame_id,
            document_id: &params.current_context.document_id,
            navigation_epoch: params.current_context.navigation_epoch,
        };

        let (mut capability, recipe_id, provider_locator) = {
            let caps = self.capabilities.lock().unwrap();
            let entry = caps
                .values()
                .find(|e| e.token == params.capability_token)
                .ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::CAPABILITY_CONSUMED,
                        "Invalid or unknown capability token",
                    )
                })?;

            (
                entry.capability.clone(),
                entry.recipe_id.clone(),
                entry.provider_locator.clone(),
            )
        };
        let claims = verify_and_consume_capability(
            &mut capability,
            &params.capability_token,
            &pub_key,
            &context_snapshot,
            now,
        )
        .map_err(|e| match e {
            secretctl_capability::CapabilityError::Expired(_) => {
                RpcError::new(RpcErrorCode::CAPABILITY_EXPIRED, "Capability expired")
            }
            secretctl_capability::CapabilityError::AlreadyConsumed { .. } => RpcError::new(
                RpcErrorCode::CAPABILITY_CONSUMED,
                "Capability already consumed",
            ),
            secretctl_capability::CapabilityError::EpochMismatch { .. } => {
                RpcError::new(RpcErrorCode::EPOCH_INVALIDATED, "Epoch mismatch")
            }
            secretctl_capability::CapabilityError::BindingMismatch { .. } => {
                RpcError::new(RpcErrorCode::ORIGIN_MISMATCH, "Context binding mismatch")
            }
            _ => RpcError::new(RpcErrorCode::SECURITY_VIOLATION, "Capability rejected"),
        })?;

        let execution_id = ExecutionId::new();
        let execution = Execution {
            execution_id: execution_id.clone(),
            capability_id: claims.jti.clone(),
            state: ExecutionState::Consuming,
            prepared_context_digest: None,
            started_at: Some(now),
            completed_at: None,
            result_code: None,
        };
        let consume_audit_context = AuditContext {
            request_id: Some(claims.req_id.to_string()),
            credential_id: Some(claims.cred_id.to_string()),
            capability_id: Some(claims.jti.to_string()),
            browser_session_id: Some(claims.browser_session_id.to_string()),
            target_origin: Some(claims.top_origin.to_string()),
            action: Some(claims.action.to_string()),
            decision: None,
            risk_level: None,
            error_code: None,
        };
        {
            let mut cursor = self.audit_cursor.lock().unwrap();
            let audit_event = create_audit_event(
                cursor.next_sequence,
                &cursor.latest_hash,
                self.audit_key_version,
                self.audit_key.as_bytes(),
                "capability.consumed",
                "executor",
                None,
                &consume_audit_context,
                Utc::now(),
            )
            .map_err(|_| RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Audit unavailable"))?;
            self.store
                .consume_capability_with_execution_and_audit(&claims.jti, &execution, &audit_event)
                .map_err(|error| match error {
                    secretctl_store::StoreError::StateConflict(_) => RpcError::new(
                        RpcErrorCode::CAPABILITY_CONSUMED,
                        "Capability already consumed",
                    ),
                    _ => RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Durable consume unavailable"),
                })?;
            cursor.next_sequence += 1;
            cursor.latest_hash = audit_event.event_hash;
        }
        if let Some(entry) = self.capabilities.lock().unwrap().get_mut(&claims.jti) {
            entry.capability = capability;
        }
        self.executions.lock().unwrap().insert(
            execution_id.clone(),
            ActiveExecution {
                execution,
                request_id: claims.req_id.clone(),
                agent_id: claims.agent_id.clone(),
                credential_id: claims.cred_id.clone(),
                action: claims.action,
            },
        );

        let recipe = {
            let recipes = self.recipes.read().unwrap();
            recipes.get(&recipe_id).cloned().ok_or_else(|| {
                RpcError::new(
                    RpcErrorCode::RECIPE_NOT_FOUND,
                    "Bound recipe is unavailable",
                )
            })?
        };

        if recipe.fields.is_empty() || recipe.fields.len() > 5 {
            return Err(RpcError::new(
                RpcErrorCode::SECURITY_VIOLATION,
                "Recipe field count is outside the supported security limit",
            ));
        }

        // Retrieve secret bytes or compute TOTP based on action kind
        let fields = match claims.action {
            ActionKind::AuthenticateTotp => {
                let seed_bytes =
                    self.provider
                        .get_secret(&provider_locator)
                        .await
                        .map_err(|_| {
                            RpcError::new(
                                RpcErrorCode::INTERNAL_ERROR,
                                "Secret provider unavailable",
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

                recipe
                    .fields
                    .iter()
                    .map(|field| ResolvedFieldInjection {
                        role: field.role.clone(),
                        selector: field.selector.clone(),
                        optional: field.optional,
                        clear_first: field.clear_first,
                        encrypted_value: totp_code.clone(),
                    })
                    .collect()
            }
            ActionKind::FormSensitiveFill => {
                let secret_bytes =
                    self.provider
                        .get_secret(&provider_locator)
                        .await
                        .map_err(|_| {
                            RpcError::new(
                                RpcErrorCode::INTERNAL_ERROR,
                                "Secret provider unavailable",
                            )
                        })?;
                let role_values: Option<HashMap<String, String>> =
                    serde_json::from_slice(secret_bytes.as_bytes()).ok();
                recipe
                    .fields
                    .iter()
                    .map(|field| {
                        let value = role_values
                            .as_ref()
                            .and_then(|values| values.get(&field.role).cloned())
                            .or_else(|| {
                                (recipe.fields.len() == 1).then(|| {
                                    String::from_utf8_lossy(secret_bytes.as_bytes()).to_string()
                                })
                            })
                            .ok_or_else(|| {
                                RpcError::new(
                                    RpcErrorCode::SECURITY_VIOLATION,
                                    "Sensitive form provider item is missing a recipe role",
                                )
                            })?;
                        Ok(ResolvedFieldInjection {
                            role: field.role.clone(),
                            selector: field.selector.clone(),
                            optional: field.optional,
                            clear_first: field.clear_first,
                            encrypted_value: value,
                        })
                    })
                    .collect::<Result<Vec<_>, RpcError>>()?
            }
            _ => {
                let secret_bytes =
                    self.provider
                        .get_secret(&provider_locator)
                        .await
                        .map_err(|_| {
                            RpcError::new(
                                RpcErrorCode::INTERNAL_ERROR,
                                "Secret provider unavailable",
                            )
                        })?;
                recipe
                    .fields
                    .iter()
                    .filter(|field| field.role == "password")
                    .map(|field| ResolvedFieldInjection {
                        role: field.role.clone(),
                        selector: field.selector.clone(),
                        optional: field.optional,
                        clear_first: field.clear_first,
                        encrypted_value: String::from_utf8_lossy(secret_bytes.as_bytes())
                            .to_string(),
                    })
                    .collect()
            }
        };

        if fields.is_empty() {
            return Err(RpcError::new(
                RpcErrorCode::SECURITY_VIOLATION,
                "Recipe does not declare a field for this action",
            ));
        }

        // Audit secret accessed
        self.record_audit_event(
            "secret.retrieve_succeeded",
            "broker",
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

        Ok(ExecutorConsumeResult {
            execution_id,
            recipe_id,
            fields,
            auto_submit_selector: recipe.submit.and_then(|submit| {
                if submit.auto_submit {
                    submit.selector
                } else {
                    None
                }
            }),
        })
    }

    pub async fn handle_executor_result(
        &self,
        params: ExecutorResultParams,
    ) -> Result<ExecutorResultResult, RpcError> {
        let (req_id, cap_id, cred_id, act) = {
            let execs = self.executions.lock().unwrap();
            let active = execs.get(&params.execution_id).ok_or_else(|| {
                RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown execution ID")
            })?;
            (
                active.request_id.clone(),
                active.execution.capability_id.clone(),
                active.credential_id.clone(),
                active.action,
            )
        };

        let mut completed_execution = {
            let execs = self.executions.lock().unwrap();
            execs
                .get(&params.execution_id)
                .ok_or_else(|| RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown execution ID"))?
                .execution
                .clone()
        };
        completed_execution.state = if params.status == "completed" {
            ExecutionState::Completed
        } else {
            ExecutionState::Failed
        };
        completed_execution.completed_at = Some(Utc::now());
        completed_execution.result_code = Some(params.result_code.clone());
        let completion_context = AuditContext {
            request_id: Some(req_id.to_string()),
            credential_id: Some(cred_id.to_string()),
            capability_id: Some(cap_id.to_string()),
            browser_session_id: None,
            target_origin: None,
            action: Some(act.to_string()),
            decision: None,
            risk_level: None,
            error_code: if params.status == "failed" {
                Some(params.result_code.clone())
            } else {
                None
            },
        };
        {
            let mut cursor = self.audit_cursor.lock().unwrap();
            let audit_event = create_audit_event(
                cursor.next_sequence,
                &cursor.latest_hash,
                self.audit_key_version,
                self.audit_key.as_bytes(),
                if params.status == "completed" {
                    "execution.completed"
                } else {
                    "execution.failed"
                },
                "executor",
                None,
                &completion_context,
                Utc::now(),
            )
            .map_err(|_| RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Audit unavailable"))?;
            self.store
                .finish_execution_with_audit(&completed_execution, &audit_event)
                .map_err(|_| {
                    RpcError::new(
                        RpcErrorCode::INTERNAL_ERROR,
                        "Durable execution result unavailable",
                    )
                })?;
            cursor.next_sequence += 1;
            cursor.latest_hash = audit_event.event_hash;
        }
        {
            let mut execs = self.executions.lock().unwrap();
            let active = execs.get_mut(&params.execution_id).ok_or_else(|| {
                RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown execution ID")
            })?;
            active.execution = completed_execution;
        }

        if let Some(request) = self.requests.write().unwrap().get_mut(&req_id) {
            request.state = if params.status == "completed" {
                ActionRequestState::Completed
            } else {
                ActionRequestState::Failed
            };
            request.result_code = Some(params.result_code.clone());
            request.execution_id = Some(params.execution_id.clone());
            request.completed_at = Some(Utc::now().to_rfc3339());
        }

        Ok(ExecutorResultResult { acknowledged: true })
    }

    pub async fn handle_executor_heartbeat(
        &self,
        params: ExecutorHeartbeatParams,
    ) -> Result<ExecutorHeartbeatResult, RpcError> {
        let mut sessions = self.sessions.write().unwrap();
        let session_entry = sessions
            .entry(params.browser_session_id.clone())
            .or_insert_with(|| ActiveBrowserSession {
                session: BrowserSession {
                    session_id: params.browser_session_id.clone(),
                    instance_id: secretctl_domain::BrowserInstanceId::new(),
                    extension_key_id: "ext-packaged-key".to_string(),
                    profile_id: "default_profile".to_string(),
                    assurance: "managed".to_string(),
                    state: BrowserSessionState::Active,
                    last_heartbeat_at: Utc::now(),
                },
                active_tab_count: params.active_tab_count,
            });
        session_entry.session.last_heartbeat_at = Utc::now();
        session_entry.active_tab_count = params.active_tab_count;
        session_entry.session.state = BrowserSessionState::Active;
        Ok(ExecutorHeartbeatResult { acknowledged: true })
    }

    pub fn expire_stale_sessions(&self, now: chrono::DateTime<Utc>) -> Result<usize, RpcError> {
        let stale_session_ids = {
            let mut sessions = self.sessions.write().unwrap();
            sessions
                .iter_mut()
                .filter_map(|(session_id, active)| {
                    if active.session.state == BrowserSessionState::Active
                        && now - active.session.last_heartbeat_at >= chrono::Duration::seconds(10)
                    {
                        active.session.state = BrowserSessionState::Stale;
                        Some(session_id.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };

        if stale_session_ids.is_empty() {
            return Ok(0);
        }

        let mut capabilities = self.capabilities.lock().unwrap();
        for entry in capabilities.values_mut() {
            if stale_session_ids.contains(&entry.capability.browser_session_id)
                && !entry.capability.state.is_terminal()
            {
                entry.capability.state = secretctl_domain::CapabilityState::Revoked;
                entry.capability.revoked_reason = Some("session_stale".to_string());
            }
        }
        drop(capabilities);

        for session_id in &stale_session_ids {
            self.record_audit_event(
                "browser.stale",
                "broker",
                None,
                &AuditContext {
                    request_id: None,
                    credential_id: None,
                    capability_id: None,
                    browser_session_id: Some(session_id.to_string()),
                    target_origin: None,
                    action: None,
                    decision: Some("revoke_session_capabilities".to_string()),
                    risk_level: None,
                    error_code: Some("SESSION_STALE".to_string()),
                },
            )?;
        }
        Ok(stale_session_ids.len())
    }

    pub fn replace_policy(&self, evaluator: PolicyEvaluator) -> Result<usize, RpcError> {
        let new_hash = evaluator.policy_hash().to_vec();
        let policy_context = AuditContext {
            request_id: None,
            credential_id: None,
            capability_id: None,
            browser_session_id: None,
            target_origin: None,
            action: None,
            decision: Some("policy_hash_changed".to_string()),
            risk_level: None,
            error_code: None,
        };
        let revoked = {
            let mut cursor = self.audit_cursor.lock().unwrap();
            let audit_event = create_audit_event(
                cursor.next_sequence,
                &cursor.latest_hash,
                self.audit_key_version,
                self.audit_key.as_bytes(),
                "policy.reloaded",
                "admin",
                None,
                &policy_context,
                Utc::now(),
            )
            .map_err(|_| RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Audit unavailable"))?;
            let revoked = self
                .store
                .revoke_capabilities_not_policy_with_audit(&new_hash, &audit_event)
                .map_err(|_| {
                    RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Policy reload unavailable")
                })?;
            cursor.next_sequence += 1;
            cursor.latest_hash = audit_event.event_hash;
            revoked
        };
        *self.policy_evaluator.write().unwrap() = evaluator;
        for entry in self.capabilities.lock().unwrap().values_mut() {
            if entry.capability.policy_hash != new_hash && !entry.capability.state.is_terminal() {
                entry.capability.state = secretctl_domain::CapabilityState::Revoked;
                entry.capability.revoked_reason = Some("policy_changed".to_string());
            }
        }
        Ok(revoked)
    }

    pub fn list_capabilities(
        &self,
        state: Option<&str>,
    ) -> Result<Vec<secretctl_domain::CapabilitySummary>, RpcError> {
        self.store.list_capabilities(state).map_err(|_| {
            RpcError::new(
                RpcErrorCode::INTERNAL_ERROR,
                "Capability storage unavailable",
            )
        })
    }

    pub fn revoke_capability_admin(
        &self,
        capability_id: &CapabilityId,
        reason: &str,
    ) -> Result<(), RpcError> {
        let context = AuditContext {
            request_id: None,
            credential_id: None,
            capability_id: Some(capability_id.to_string()),
            browser_session_id: None,
            target_origin: None,
            action: None,
            decision: Some("admin_revoked".to_string()),
            risk_level: None,
            error_code: None,
        };
        {
            let mut cursor = self.audit_cursor.lock().unwrap();
            let event = create_audit_event(
                cursor.next_sequence,
                &cursor.latest_hash,
                self.audit_key_version,
                self.audit_key.as_bytes(),
                "capability.revoked",
                "admin",
                None,
                &context,
                Utc::now(),
            )
            .map_err(|_| RpcError::new(RpcErrorCode::INTERNAL_ERROR, "Audit unavailable"))?;
            self.store
                .revoke_capability_with_audit(capability_id, reason, &event)
                .map_err(|_| {
                    RpcError::new(RpcErrorCode::INVALID_PARAMS, "Capability is not active")
                })?;
            cursor.next_sequence += 1;
            cursor.latest_hash = event.event_hash;
        }
        if let Some(entry) = self.capabilities.lock().unwrap().get_mut(capability_id) {
            entry.capability.state = secretctl_domain::CapabilityState::Revoked;
            entry.capability.revoked_reason = Some(reason.to_string());
        }
        Ok(())
    }
}
