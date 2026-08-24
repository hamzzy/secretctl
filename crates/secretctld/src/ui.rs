//! Projections from broker state onto the UI-safe DTOs in
//! [`secretctl_protocol::admin`].
//!
//! The desktop UI never sees a domain entity. Every method here takes the
//! internal state and narrows it to what a human needs in order to make or
//! review an authorization decision, dropping provider locators, capability
//! tokens, enrollment keys, and raw audit bodies on the way out.
//!
//! Nothing in this module makes an authorization decision. Approve, deny, and
//! grant creation all funnel back into the existing kernel paths in
//! [`crate::state`], which re-verify every precondition independently of
//! whatever the UI believed when it rendered the button.

use crate::state::BrokerState;
use base64::Engine;
use chrono::Utc;
use secretctl_audit::AuditContext;
use secretctl_domain::{
    ActionKind, AgentId, ApprovalId, BrowserSessionState, CapabilityState, ExecutionState,
    GrantId, MAX_GRANT_TTL_DAYS, MAX_GRANTABLE_RISK, RiskLevel, StandingGrant,
};
use secretctl_protocol::{
    GrantCreateParams, GrantCreateResult, GrantRevokeResult, ReasonSource, RpcError, RpcErrorCode,
    UiActiveOperation, UiActivityEvent, UiAgent, UiAuthorizationRequest, UiBrowserSession,
    UiCredential, UiEventOutcome, UiFlowStep, UiGrant, UiOperationStep, UiProtectionState,
    UiStatus, UiStepState, action_label,
};
use std::collections::{HashMap, HashSet};

/// Longest an agent-supplied string may be before the UI truncates it. The
/// broker already caps `reason` at 500 characters on ingress; this is the
/// second, independent clamp so a stored value can never blow up the panel.
const MAX_AGENT_TEXT_CHARS: usize = 500;

/// How long a terminal operation keeps showing its Completed/Blocked state
/// before the menu bar settles back to Protected.
const TERMINAL_STATE_LINGER_SECONDS: i64 = 8;

/// Clamp and sanitize a string that an agent controls.
///
/// Control characters and bidirectional overrides are stripped rather than
/// escaped: an agent must not be able to reorder or overlay the surrounding
/// UI text, and there is no legitimate reason for such a character to appear
/// in a justification.
fn sanitize_agent_text(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .filter(|character| {
            !character.is_control()
                && !matches!(*character, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .take(MAX_AGENT_TEXT_CHARS)
        .collect();
    cleaned.trim().to_string()
}

fn internal(message: &'static str) -> RpcError {
    RpcError::new(RpcErrorCode::INTERNAL_ERROR, message)
}

/// Map a provider identifier onto the name shown in the UI. The identifier
/// itself is an implementation detail of the provider registry.
fn provider_label(provider: &str) -> String {
    match provider {
        "macos-keychain" | "macos" | "keychain" => "macOS Keychain".to_string(),
        "1password" | "onepassword" => "1Password".to_string(),
        "vault" | "hashicorp-vault" => "HashiCorp Vault".to_string(),
        other => other.to_string(),
    }
}

impl BrokerState {
    // -----------------------------------------------------------------
    // Pending authorization
    // -----------------------------------------------------------------

    /// Pending approvals, enriched into the payload the approval panel needs.
    ///
    /// The raw [`secretctl_domain::Approval`] carries only ids and a digest,
    /// which is not enough for a human to decide anything. The fields a human
    /// actually reasons about live in the retained `AuthorizationContext`, so
    /// they are projected here — every one of them broker-measured except
    /// `reason`, which is tagged [`ReasonSource::AgentProvided`].
    pub fn ui_pending_approvals(&self) -> Result<Vec<UiAuthorizationRequest>, RpcError> {
        let now = Utc::now();
        let approvals = self.approvals.lock().unwrap();
        let mut pending: Vec<_> = approvals
            .values()
            .filter(|entry| entry.approval.decision == "pending" && entry.approval.expires_at > now)
            .cloned()
            .collect();
        drop(approvals);
        pending.sort_by_key(|entry| entry.approval.expires_at);

        // An agent is "first-seen" when nothing in the audit trail records a
        // prior issued capability for it. Computed once for the whole batch.
        let agents_with_history = self.agents_with_prior_authorization()?;

        Ok(pending
            .into_iter()
            .map(|entry| {
                let authorization = &entry.authorization;
                // Shown to the human: the risk of the operation itself, not the
                // High that the presence requirement mechanically implies.
                let risk = authorization.base_risk;
                let requires_presence = authorization.decision.require_user_presence;
                UiAuthorizationRequest {
                    approval_id: entry.approval.approval_id.to_string(),
                    request_id: entry.approval.request_id.to_string(),
                    agent_name: sanitize_agent_text(&authorization.agent_name),
                    agent_id: authorization.agent_id.to_string(),
                    credential_name: authorization.credential.name.clone(),
                    provider: provider_label(&authorization.credential.provider),
                    origin: authorization.page_context.top_origin.to_string(),
                    action: authorization.action,
                    action_label: action_label(authorization.action).to_string(),
                    flow_steps: authorization
                        .recipe
                        .fields
                        .iter()
                        .map(|field| UiFlowStep {
                            role: field.role.clone(),
                            label: UiFlowStep::label_for(&field.role),
                            optional: field.optional,
                        })
                        .collect(),
                    risk,
                    reason: Some(sanitize_agent_text(&authorization.reason))
                        .filter(|text| !text.is_empty()),
                    reason_source: ReasonSource::AgentProvided,
                    context_digest: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(&entry.approval.context_digest),
                    expires_at: entry.approval.expires_at,
                    requires_presence,
                    is_first_for_agent: !agents_with_history.contains(&authorization.agent_id),
                    // A grant may only ever cover risk at or below the global
                    // ceiling, and never a decision that demands live presence.
                    grantable: risk.rank() <= MAX_GRANTABLE_RISK.rank(),
                }
            })
            .collect())
    }

    /// Agents that have previously had a capability minted for them.
    ///
    /// `capability.minted` records no actor — it is emitted by the broker, not
    /// the agent — so the link is made through `request_id`, which
    /// `action.requested` ties to the requesting agent. Counting
    /// `action.requested` alone would be wrong: the request being decided right
    /// now is already in the trail, and every agent would look familiar.
    fn agents_with_prior_authorization(&self) -> Result<HashSet<AgentId>, RpcError> {
        let events = self
            .store
            .list_audit_events()
            .map_err(|_| internal("Audit storage unavailable"))?;

        let mut request_agents: HashMap<String, AgentId> = HashMap::new();
        let mut authorized_requests: HashSet<String> = HashSet::new();
        for event in &events {
            let Ok(context) = serde_json::from_str::<AuditContext>(&event.event_json) else {
                continue;
            };
            let Some(request_id) = context.request_id else {
                continue;
            };
            match event.event_type.as_str() {
                "action.requested" => {
                    if let Some(agent) = event
                        .actor_id
                        .as_deref()
                        .and_then(|actor| AgentId::parse(actor).ok())
                    {
                        request_agents.insert(request_id, agent);
                    }
                }
                "capability.minted" => {
                    authorized_requests.insert(request_id);
                }
                _ => {}
            }
        }

        Ok(authorized_requests
            .iter()
            .filter_map(|request_id| request_agents.get(request_id).cloned())
            .collect())
    }

    // -----------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------

    /// Snapshot for the menu-bar icon and popover header.
    pub fn ui_status(&self) -> Result<UiStatus, RpcError> {
        let now = Utc::now();
        let pending = self.ui_pending_approvals()?;
        let active_operation = self.ui_active_operation();

        let sessions = self.sessions.read().unwrap();
        let browser_sessions_connected = sessions
            .values()
            .filter(|active| active.session.state == BrowserSessionState::Active)
            .count() as u32;
        drop(sessions);

        let agents = self
            .store
            .list_agents()
            .map_err(|_| internal("Agent storage unavailable"))?;
        let grants = self
            .store
            .list_standing_grants(false)
            .map_err(|_| internal("Grant storage unavailable"))?;
        let active_grants = grants
            .iter()
            .filter(|grant| grant.is_active_at(now))
            .count() as u32;

        let credentials = self
            .store
            .list_credentials()
            .map_err(|_| internal("Credential storage unavailable"))?;
        let mut providers: Vec<String> = credentials
            .iter()
            .filter(|credential| credential.disabled_at.is_none())
            .map(|credential| provider_label(&credential.provider))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        providers.sort();

        // Agents that have touched the broker recently enough to be worth
        // showing as "active" rather than merely enrolled.
        let recent_actors = self.recent_actor_ids(chrono::Duration::minutes(30))?;
        let agents_active = agents
            .iter()
            .filter(|agent| recent_actors.contains_key(agent.agent_id.as_str()))
            .count() as u32;

        let protection = self.ui_protection_state(&pending, active_operation.as_ref(), now)?;

        Ok(UiStatus {
            protection,
            pending_approvals: pending.len() as u32,
            active_operation,
            browser_sessions_connected,
            agents_enrolled: agents.len() as u32,
            agents_active,
            active_grants,
            providers,
            policy_fingerprint: self.ui_policy_fingerprint(),
            audit_chain_intact: self.verify_audit_integrity().is_ok(),
        })
    }

    fn ui_policy_fingerprint(&self) -> String {
        let evaluator = self.policy_evaluator.read().unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(evaluator.policy_hash())
            .chars()
            .take(12)
            .collect()
    }

    /// Decide which state the menu-bar icon should show.
    ///
    /// Ordering matters: a fail-closed condition outranks anything cosmetic, so
    /// an interrupted or unverifiable operation is reported even while other
    /// requests are queued behind it.
    fn ui_protection_state(
        &self,
        pending: &[UiAuthorizationRequest],
        active: Option<&UiActiveOperation>,
        now: chrono::DateTime<Utc>,
    ) -> Result<UiProtectionState, RpcError> {
        if let Some(operation) = active {
            if !operation.protection_verified {
                return Ok(UiProtectionState::ProtectionInterrupted);
            }
            return Ok(UiProtectionState::SensitiveOperation);
        }

        // A capability revoked because its browser session went stale means the
        // broker lost the ability to verify protection mid-flight. That is not
        // a plain failure, and it is not a success either.
        let capabilities = self.capabilities.lock().unwrap();
        let interrupted = capabilities.values().any(|entry| {
            entry.capability.state == CapabilityState::Revoked
                && entry.capability.revoked_reason.as_deref() == Some("session_stale")
                && now - entry.capability.issued_at
                    <= chrono::Duration::seconds(TERMINAL_STATE_LINGER_SECONDS)
        });
        drop(capabilities);
        if interrupted {
            return Ok(UiProtectionState::ProtectionInterrupted);
        }

        if !pending.is_empty() {
            return Ok(UiProtectionState::ApprovalRequired);
        }

        // Linger briefly on the outcome of the most recent terminal event so
        // the user sees the confirmation without having to catch it live.
        if let Some(recent) = self.most_recent_terminal_outcome(now)? {
            return Ok(recent);
        }

        Ok(UiProtectionState::Protected)
    }

    fn most_recent_terminal_outcome(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<Option<UiProtectionState>, RpcError> {
        // An execution the broker could not resolve either way outranks any
        // audit row: claiming success or failure there would be a guess.
        let executions = self.executions.lock().unwrap();
        let uncertain = executions.values().any(|active| {
            active.execution.state == ExecutionState::Indeterminate
                && active
                    .execution
                    .completed_at
                    .is_some_and(|at| now - at <= chrono::Duration::seconds(TERMINAL_STATE_LINGER_SECONDS))
        });
        drop(executions);
        if uncertain {
            return Ok(Some(UiProtectionState::OutcomeUncertain));
        }

        let events = self
            .store
            .list_audit_events()
            .map_err(|_| internal("Audit storage unavailable"))?;
        let Some(latest) = events.last() else {
            return Ok(None);
        };
        if now - latest.created_at > chrono::Duration::seconds(TERMINAL_STATE_LINGER_SECONDS) {
            return Ok(None);
        }
        Ok(match latest.event_type.as_str() {
            "execution.completed" => Some(UiProtectionState::Completed),
            "execution.failed"
            | "approval.denied"
            | "approval.expired"
            | "capability.revoked" => Some(UiProtectionState::Blocked),
            "approval.invalidated" => Some(UiProtectionState::ProtectionInterrupted),
            _ => None,
        })
    }

    /// The credential operation currently in flight, if any.
    ///
    /// `confirmed_protections` is populated only from state the executor has
    /// actually reported. The UI is forbidden from asserting a protection is
    /// active on its own, so an unverifiable session yields an empty list
    /// rather than an optimistic one.
    pub fn ui_active_operation(&self) -> Option<UiActiveOperation> {
        let now = Utc::now();
        let executions = self.executions.lock().unwrap();
        let active = executions.values().find(|execution| {
            !execution.execution.state.is_terminal() && execution.execution.started_at.is_some()
        })?;
        let request_id = active.request_id.clone();
        let action = active.action;
        let agent_id = active.agent_id.clone();
        let credential_id = active.credential_id.clone();
        let capability_id = active.execution.capability_id.clone();
        drop(executions);

        let capabilities = self.capabilities.lock().unwrap();
        let entry = capabilities.get(&capability_id)?;
        let session_id = entry.capability.browser_session_id.clone();
        let origin = entry.capability.top_origin.to_string();
        let used_count = entry.capability.used_count;
        let max_uses = entry.capability.max_uses;
        let recipe = self.recipes.read().unwrap().get(&entry.recipe_id).cloned();
        drop(capabilities);

        let sessions = self.sessions.read().unwrap();
        let protection_verified = sessions.get(&session_id).is_some_and(|active_session| {
            active_session.session.state == BrowserSessionState::Active
                && now - active_session.session.last_heartbeat_at < chrono::Duration::seconds(10)
        });
        drop(sessions);

        let agent_name = self
            .store
            .get_enrolled_agent(agent_id.as_str())
            .map(|principal| sanitize_agent_text(&principal.display_name))
            .unwrap_or_else(|_| agent_id.to_string());
        let credential_name = self
            .store
            .list_credentials()
            .ok()
            .and_then(|credentials| {
                credentials
                    .into_iter()
                    .find(|credential| credential.credential_id == credential_id)
                    .map(|credential| credential.name)
            })
            .unwrap_or_else(|| "credential".to_string());

        // Progress is derived from how many of the capability's permitted uses
        // have been consumed, which is the only count the broker actually has.
        let steps = recipe
            .map(|recipe| {
                recipe
                    .fields
                    .iter()
                    .enumerate()
                    .map(|(index, field)| UiOperationStep {
                        label: UiFlowStep::label_for(&field.role),
                        state: if (index as u32) < used_count {
                            UiStepState::Done
                        } else if index as u32 == used_count && used_count < max_uses {
                            UiStepState::Active
                        } else {
                            UiStepState::Pending
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();

        let confirmed_protections = if protection_verified {
            vec![
                "Screenshots blocked".to_string(),
                "Screen capture blocked".to_string(),
                "DOM extraction blocked".to_string(),
                "Accessibility extraction blocked".to_string(),
                "Credential isolated".to_string(),
            ]
        } else {
            Vec::new()
        };

        Some(UiActiveOperation {
            request_id: request_id.to_string(),
            agent_name,
            credential_name,
            origin,
            action_label: action_label(action).to_string(),
            steps,
            confirmed_protections,
            protection_verified,
        })
    }

    // -----------------------------------------------------------------
    // Activity
    // -----------------------------------------------------------------

    /// Recent audit events, projected for the activity list.
    ///
    /// The raw `event_json` body is parsed here and discarded; only the handful
    /// of fields a row displays cross the socket.
    pub fn ui_activity(&self, limit: u32) -> Result<Vec<UiActivityEvent>, RpcError> {
        let events = self
            .store
            .list_audit_events()
            .map_err(|_| internal("Audit storage unavailable"))?;
        let agent_names = self.agent_display_names();

        let mut rows: Vec<UiActivityEvent> = events
            .iter()
            .rev()
            .take(limit.clamp(1, 500) as usize)
            .map(|event| {
                let context: AuditContext = serde_json::from_str(&event.event_json)
                    .unwrap_or_else(|_| empty_audit_context());
                let action = context
                    .action
                    .as_deref()
                    .and_then(|value| value.parse::<ActionKind>().ok());
                UiActivityEvent {
                    sequence: event.sequence,
                    event_id: event.event_id.to_string(),
                    event_type: event.event_type.clone(),
                    summary: summarize_event(&event.event_type, context.target_origin.as_deref()),
                    outcome: classify_event(&event.event_type, context.decision.as_deref()),
                    actor_type: event.actor_type.clone(),
                    actor_name: event.actor_id.as_ref().map(|actor| {
                        agent_names
                            .get(actor.as_str())
                            .cloned()
                            .unwrap_or_else(|| actor.clone())
                    }),
                    origin: context.target_origin.clone(),
                    action,
                    risk: context
                        .risk_level
                        .as_deref()
                        .and_then(|value| value.parse::<RiskLevel>().ok()),
                    error_code: context.error_code.clone(),
                    created_at: event.created_at,
                }
            })
            .collect();
        rows.sort_by(|left, right| right.sequence.cmp(&left.sequence));
        Ok(rows)
    }

    fn agent_display_names(&self) -> HashMap<String, String> {
        self.store
            .list_agents()
            .map(|agents| {
                agents
                    .into_iter()
                    .map(|agent| {
                        (
                            agent.agent_id.to_string(),
                            sanitize_agent_text(&agent.display_name),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn recent_actor_ids(
        &self,
        window: chrono::Duration,
    ) -> Result<HashMap<String, chrono::DateTime<Utc>>, RpcError> {
        let now = Utc::now();
        let events = self
            .store
            .list_audit_events()
            .map_err(|_| internal("Audit storage unavailable"))?;
        let mut latest: HashMap<String, chrono::DateTime<Utc>> = HashMap::new();
        for event in events
            .iter()
            .filter(|event| now - event.created_at <= window)
        {
            if let Some(actor) = &event.actor_id {
                latest
                    .entry(actor.clone())
                    .and_modify(|existing| {
                        if event.created_at > *existing {
                            *existing = event.created_at;
                        }
                    })
                    .or_insert(event.created_at);
            }
        }
        Ok(latest)
    }

    // -----------------------------------------------------------------
    // Agents, credentials, browser sessions
    // -----------------------------------------------------------------

    pub fn ui_agents(&self) -> Result<Vec<UiAgent>, RpcError> {
        let now = Utc::now();
        let agents = self
            .store
            .list_agents()
            .map_err(|_| internal("Agent storage unavailable"))?;
        let grants = self
            .store
            .list_standing_grants(false)
            .map_err(|_| internal("Grant storage unavailable"))?;
        let events = self
            .store
            .list_audit_events()
            .map_err(|_| internal("Audit storage unavailable"))?;

        Ok(agents
            .into_iter()
            .map(|agent| {
                let agent_key = agent.agent_id.to_string();
                let agent_events: Vec<_> = events
                    .iter()
                    .filter(|event| event.actor_id.as_deref() == Some(agent_key.as_str()))
                    .collect();
                UiAgent {
                    active_grants: grants
                        .iter()
                        .filter(|grant| grant.agent_id == agent.agent_id && grant.is_active_at(now))
                        .count() as u32,
                    recent_event_count: agent_events.len() as u32,
                    last_activity_at: agent_events.last().map(|event| event.created_at),
                    agent_id: agent_key,
                    display_name: sanitize_agent_text(&agent.display_name),
                    role: agent.role,
                    state: agent.state,
                    created_at: agent.created_at,
                }
            })
            .collect())
    }

    /// Credential *references*. No secret and no provider locator leaves here,
    /// which is what keeps the credentials screen from becoming a vault.
    pub fn ui_credentials(&self) -> Result<Vec<UiCredential>, RpcError> {
        let now = Utc::now();
        let credentials = self
            .store
            .list_credentials()
            .map_err(|_| internal("Credential storage unavailable"))?;
        let grants = self
            .store
            .list_standing_grants(false)
            .map_err(|_| internal("Grant storage unavailable"))?;

        Ok(credentials
            .into_iter()
            .map(|credential| {
                let related: Vec<&StandingGrant> = grants
                    .iter()
                    .filter(|grant| grant.credential_name == credential.name)
                    .collect();
                let mut approved_origins: Vec<String> = related
                    .iter()
                    .filter(|grant| grant.is_active_at(now))
                    .map(|grant| grant.origin.to_string())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                approved_origins.sort();
                let mut used_by: Vec<String> = related
                    .iter()
                    .map(|grant| sanitize_agent_text(&grant.agent_name))
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                used_by.sort();

                UiCredential {
                    name: credential.name,
                    kind: credential.kind,
                    provider: provider_label(&credential.provider),
                    allowed_actions: credential.allowed_actions,
                    approved_origins,
                    used_by,
                    last_used_at: related.iter().filter_map(|grant| grant.last_used_at).max(),
                    disabled: credential.disabled_at.is_some(),
                }
            })
            .collect())
    }

    pub fn ui_browser_sessions(&self) -> Result<Vec<UiBrowserSession>, RpcError> {
        let contexts = self.page_contexts.read().unwrap();
        let sessions = self.sessions.read().unwrap();
        let mut rows: Vec<UiBrowserSession> = sessions
            .values()
            .map(|active| {
                let mut current_origins: Vec<String> = contexts
                    .get(&active.session.session_id)
                    .map(|tabs| {
                        tabs.values()
                            .map(|context| context.top_origin.to_string())
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .collect()
                    })
                    .unwrap_or_default();
                current_origins.sort();
                UiBrowserSession {
                    session_id: active.session.session_id.to_string(),
                    profile: active.session.profile_id.clone(),
                    state: active.session.state.as_str().to_string(),
                    assurance: active.session.assurance.clone(),
                    last_heartbeat_at: active.session.last_heartbeat_at,
                    active_tab_count: active.active_tab_count,
                    current_origins,
                }
            })
            .collect();
        rows.sort_by(|left, right| left.profile.cmp(&right.profile));
        Ok(rows)
    }

    // -----------------------------------------------------------------
    // Standing grants
    // -----------------------------------------------------------------

    pub fn ui_grants(&self, include_revoked: bool) -> Result<Vec<UiGrant>, RpcError> {
        let now = Utc::now();
        let grants = self
            .store
            .list_standing_grants(include_revoked)
            .map_err(|_| internal("Grant storage unavailable"))?;
        Ok(grants
            .into_iter()
            .map(|grant| ui_grant(grant, now))
            .collect())
    }

    /// Approve a pending request *and* create the standing authorization that
    /// will cover the same tuple next time.
    ///
    /// The grant is derived entirely from the approval's own
    /// `AuthorizationContext`, never from parameters the UI supplies. That is
    /// what makes it safe to expose grant creation to a frontend: the UI can
    /// only ever widen authority along a tuple the broker has just
    /// independently verified against a live, measured page.
    pub fn ui_create_grant(
        &self,
        params: GrantCreateParams,
    ) -> Result<GrantCreateResult, RpcError> {
        let now = Utc::now();
        if params.ttl_days <= 0 || params.ttl_days > MAX_GRANT_TTL_DAYS {
            return Err(RpcError::new(
                RpcErrorCode::INVALID_PARAMS,
                "Grant lifetime is outside the permitted range",
            ));
        }

        let pending = self
            .approvals
            .lock()
            .unwrap()
            .get(&params.approval_id)
            .cloned()
            .ok_or_else(|| RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown approval ID"))?;
        let authorization = pending.authorization.clone();
        // Scored without the presence escalation: see `AuthorizationContext::
        // base_risk`. Using the escalated risk here would refuse every request
        // that can reach an approval panel at all.
        let risk = authorization.base_risk;

        // The ceiling is a property of the system, not a choice offered to the
        // user: high and critical decisions always return to a human.
        if risk.rank() > MAX_GRANTABLE_RISK.rank() {
            return Err(RpcError::new(
                RpcErrorCode::AUTH_POLICY_DENIED,
                "This risk level can never be covered by a standing authorization",
            ));
        }
        if authorization.decision.require_user_presence && !params.presence_verified {
            return Err(RpcError::new(
                RpcErrorCode::APPROVAL_REJECTED,
                "Creating this authorization requires verified user presence",
            ));
        }

        // Decide first. If the kernel rejects the approval — expired digest,
        // navigated page, stale context — no grant is created.
        let decision = self.decide_approval(
            &params.approval_id,
            true,
            &params.context_digest,
            "local-admin",
            params.presence_verified,
        )?;

        let grant = StandingGrant {
            grant_id: GrantId::new(),
            agent_id: authorization.agent_id.clone(),
            agent_name: authorization.agent_name.clone(),
            credential_id: authorization.credential.credential_id.clone(),
            credential_name: authorization.credential.name.clone(),
            origin: authorization.page_context.top_origin.clone(),
            action: authorization.action,
            risk_ceiling: risk,
            // The grant exists precisely to replace the presence step, and
            // creating it already required verified presence. A grant that kept
            // the flag would match nothing and silently do nothing.
            require_presence: false,
            created_at: now,
            expires_at: now + chrono::Duration::days(params.ttl_days),
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            use_count: 0,
        };

        let context = AuditContext {
            request_id: Some(authorization.request_id.to_string()),
            credential_id: Some(authorization.credential.credential_id.to_string()),
            capability_id: None,
            browser_session_id: Some(authorization.browser_session_id.to_string()),
            target_origin: Some(grant.origin.to_string()),
            action: Some(grant.action.to_string()),
            decision: Some("grant_created".to_string()),
            risk_level: Some(risk.as_str().to_string()),
            error_code: None,
        };
        self.insert_standing_grant_audited(&grant, &context)?;

        Ok(GrantCreateResult {
            grant: ui_grant(grant, now),
            decision,
        })
    }

    /// Revoke by grant id, or in bulk by `agent:<name>` / `credential:<name>`.
    pub fn ui_revoke_grants(
        &self,
        selector: &str,
        reason: &str,
    ) -> Result<GrantRevokeResult, RpcError> {
        let selector = match selector.split_once(':') {
            Some(("agent", name)) => secretctl_store::GrantSelector::Agent(name.to_string()),
            Some(("credential", name)) => {
                secretctl_store::GrantSelector::Credential(name.to_string())
            }
            _ => secretctl_store::GrantSelector::Id(
                GrantId::parse(selector)
                    .map_err(|_| RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown grant"))?,
            ),
        };
        let revoked = self
            .store
            .revoke_standing_grants(&selector, reason, Utc::now())
            .map_err(|_| internal("Grant storage unavailable"))?;

        for grant in &revoked {
            let context = AuditContext {
                request_id: None,
                credential_id: Some(grant.credential_id.to_string()),
                capability_id: None,
                browser_session_id: None,
                target_origin: Some(grant.origin.to_string()),
                action: Some(grant.action.to_string()),
                decision: Some("grant_revoked".to_string()),
                risk_level: Some(grant.risk_ceiling.as_str().to_string()),
                error_code: None,
            };
            self.record_audit_event("grant.revoked", "admin", None, &context)?;
        }
        Ok(GrantRevokeResult {
            revoked: revoked.len() as u32,
        })
    }

    /// Disable an agent: revoke every standing authorization it holds and
    /// invalidate any capability it currently has outstanding.
    pub fn ui_disable_agent(&self, agent_id: &AgentId) -> Result<GrantRevokeResult, RpcError> {
        let agent = self
            .store
            .get_enrolled_agent(agent_id.as_str())
            .map_err(|_| RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown agent"))?;
        let revoked = self.ui_revoke_grants(
            &format!("agent:{}", agent.display_name),
            "agent disabled by user",
        )?;

        let mut capabilities = self.capabilities.lock().unwrap();
        for entry in capabilities.values_mut() {
            if &entry.capability.agent_id == agent_id && !entry.capability.state.is_terminal() {
                entry.capability.state = CapabilityState::Revoked;
                entry.capability.revoked_reason = Some("agent_disabled".to_string());
            }
        }
        drop(capabilities);

        self.record_audit_event(
            "agent.disabled",
            "admin",
            Some(agent_id.to_string()),
            &AuditContext {
                request_id: None,
                credential_id: None,
                capability_id: None,
                browser_session_id: None,
                target_origin: None,
                action: None,
                decision: Some("agent_disabled".to_string()),
                risk_level: None,
                error_code: None,
            },
        )?;
        Ok(revoked)
    }

    /// Look up one pending approval by id, so the approval window can refresh
    /// its `context_digest` immediately before the human commits.
    pub fn ui_pending_approval(
        &self,
        approval_id: &ApprovalId,
    ) -> Result<UiAuthorizationRequest, RpcError> {
        self.ui_pending_approvals()?
            .into_iter()
            .find(|request| request.approval_id == approval_id.to_string())
            .ok_or_else(|| {
                RpcError::new(
                    RpcErrorCode::INVALID_PARAMS,
                    "Approval is no longer pending",
                )
            })
    }
}

fn ui_grant(grant: StandingGrant, now: chrono::DateTime<Utc>) -> UiGrant {
    UiGrant {
        active: grant.is_active_at(now),
        grant_id: grant.grant_id.to_string(),
        agent_name: sanitize_agent_text(&grant.agent_name),
        credential_name: grant.credential_name,
        origin: grant.origin.to_string(),
        action: grant.action,
        action_label: action_label(grant.action).to_string(),
        risk_ceiling: grant.risk_ceiling,
        require_presence: grant.require_presence,
        created_at: grant.created_at,
        expires_at: grant.expires_at,
        revoked_at: grant.revoked_at,
        revoked_reason: grant.revoked_reason,
        last_used_at: grant.last_used_at,
        use_count: grant.use_count,
    }
}

fn empty_audit_context() -> AuditContext {
    AuditContext {
        request_id: None,
        credential_id: None,
        capability_id: None,
        browser_session_id: None,
        target_origin: None,
        action: None,
        decision: None,
        risk_level: None,
        error_code: None,
    }
}

/// Human summary for an activity row.
///
/// Deliberately avoids internal error codes and state-machine vocabulary; the
/// technical detail stays behind a disclosure (spec §19, §24). The arms below
/// cover the event types `secretctld` actually emits — an unrecognised type
/// degrades to a readable form rather than being hidden, so a new event never
/// silently disappears from the activity list.
fn summarize_event(event_type: &str, origin: Option<&str>) -> String {
    let site = origin
        .and_then(|value| value.split("://").nth(1))
        .map(|host| host.trim_end_matches(":443").to_string());
    match event_type {
        "action.requested" => "Credential action requested".to_string(),
        "approval.requested" => "Authorization requested".to_string(),
        "approval.approved" => "Authorization approved".to_string(),
        "approval.auto_granted" => "Approved by standing authorization".to_string(),
        "approval.denied" => "Authorization denied".to_string(),
        "approval.expired" => "Authorization request expired".to_string(),
        // The page moved under the request. Not a failure of the user's intent.
        "approval.invalidated" => "Page changed before authorization completed".to_string(),
        "capability.minted" => "Capability issued".to_string(),
        "capability.consumed" => "Credential delivered to the browser".to_string(),
        "capability.revoked" => "Capability revoked".to_string(),
        // Names the retrieval, never the value: the broker fetched a secret
        // from the provider and handed it to the executor, not to the agent.
        "secret.retrieve_succeeded" => "Credential retrieved from provider".to_string(),
        "execution.completed" => match site {
            Some(host) => format!("{host} authentication completed"),
            None => "Authentication completed".to_string(),
        },
        "execution.failed" => "Authentication blocked".to_string(),
        "policy.evaluated" => "Policy evaluated".to_string(),
        "policy.reloaded" => "Policy reloaded".to_string(),
        "browser.registered" => "Browser session connected".to_string(),
        "browser.stale" => "Protection interrupted".to_string(),
        "agent.enrolled" => "Agent enrolled".to_string(),
        "agent.disabled" => "Agent disabled".to_string(),
        "grant.created" => "Standing authorization created".to_string(),
        "grant.revoked" => "Standing authorization revoked".to_string(),
        "audit.checkpoint" => "Audit checkpoint written".to_string(),
        other => other.replace('.', " "),
    }
}

fn classify_event(event_type: &str, decision: Option<&str>) -> UiEventOutcome {
    match event_type {
        "execution.completed"
        | "approval.approved"
        | "approval.auto_granted"
        | "grant.created" => UiEventOutcome::Success,
        "approval.denied"
        | "approval.expired"
        | "execution.failed"
        | "capability.revoked"
        | "agent.disabled"
        | "grant.revoked" => UiEventOutcome::Denied,
        "approval.requested" => UiEventOutcome::Pending,
        "browser.stale" | "approval.invalidated" => UiEventOutcome::Interrupted,
        // `policy.evaluated` records both allows and denies, so the decision
        // field is what distinguishes them.
        _ => match decision {
            Some("deny") | Some("denied") | Some("invalidated") | Some("expired") => {
                UiEventOutcome::Denied
            }
            _ => UiEventOutcome::Info,
        },
    }
}

#[cfg(test)]
mod ui_projection_tests {
    use super::*;

    #[test]
    fn agent_text_is_clamped_and_stripped_of_control_characters() {
        let hostile = "Review PRs\n\u{202E}dessap noitacitnehtuA";
        let cleaned = sanitize_agent_text(hostile);
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\u{202E}'));
    }

    #[test]
    fn agent_text_is_truncated_to_the_display_limit() {
        let long = "a".repeat(MAX_AGENT_TEXT_CHARS * 2);
        assert_eq!(
            sanitize_agent_text(&long).chars().count(),
            MAX_AGENT_TEXT_CHARS
        );
    }

    #[test]
    fn provider_identifiers_map_onto_display_names() {
        assert_eq!(provider_label("macos-keychain"), "macOS Keychain");
        assert_eq!(provider_label("1password"), "1Password");
        // An unknown provider passes through rather than being mislabelled.
        assert_eq!(provider_label("custom-hsm"), "custom-hsm");
    }

    #[test]
    fn stale_browser_protection_classifies_as_interrupted_not_failed() {
        assert_eq!(
            classify_event("browser.stale", None),
            UiEventOutcome::Interrupted
        );
        // A page that navigated out from under a pending approval is likewise
        // an interruption, not a denial of what the user wanted.
        assert_eq!(
            classify_event("approval.invalidated", None),
            UiEventOutcome::Interrupted
        );
    }

    #[test]
    fn summaries_never_leak_internal_error_vocabulary() {
        for event_type in [
            "approval.denied",
            "approval.expired",
            "approval.invalidated",
            "execution.failed",
            "browser.stale",
            "capability.revoked",
        ] {
            let summary = summarize_event(event_type, Some("https://github.com:443"));
            assert!(!summary.contains("EPOCH"));
            assert!(!summary.contains("-32"));
            assert!(!summary.contains('_'));
        }
    }
}
