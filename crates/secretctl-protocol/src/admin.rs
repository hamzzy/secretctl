//! UI-facing DTOs and admin RPC parameters.
//!
//! Everything in this module crosses the admin socket to the desktop UI. The
//! internal domain entities are deliberately *not* reused here: several of them
//! carry secret-bearing or capability-bearing fields (`CredentialDescriptor::
//! provider_locator`, `Capability::token_hash`, `AgentPrincipal::public_key`)
//! that must never reach a frontend process. Every type below is constructed by
//! projecting a domain entity down to the fields a human needs in order to make
//! an authorization decision.
//!
//! The rule this module exists to enforce: **no field here may ever hold
//! credential material, a capability token, a provider locator, or a key.**
//! `admin_dto_tests` asserts that mechanically.

use secretctl_domain::{ActionKind, ApprovalId, CapabilityId, RiskLevel};
use serde::{Deserialize, Serialize};

/// Whether a string shown in the UI was produced by the broker or supplied by
/// the requesting agent.
///
/// The distinction is a security boundary, not a presentation detail: an agent
/// controls its own `reason` text and could otherwise write something that
/// reads like broker-verified truth ("Verified by secretctl"). The UI renders
/// anything marked [`ReasonSource::AgentProvided`] as quoted, attributed,
/// plain text so it can never impersonate system chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonSource {
    /// Free-form text the agent sent. Untrusted. Render as attributed quotation.
    AgentProvided,
}

/// One step of the authentication flow a recipe will perform.
///
/// Derived from the matched recipe's fields, so it reflects what the executor
/// will actually do rather than what the agent claimed it wanted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiFlowStep {
    /// Recipe field role, e.g. `password`, `totp`, `username`.
    pub role: String,
    /// Human label for the role, e.g. "Password", "TOTP".
    pub label: String,
    /// Whether the recipe may skip this step.
    pub optional: bool,
}

impl UiFlowStep {
    /// Map a recipe field role onto the label shown in the approval panel.
    pub fn label_for(role: &str) -> String {
        match role {
            "password" => "Password".to_string(),
            "totp" => "TOTP".to_string(),
            "username" => "Username".to_string(),
            "email" => "Email".to_string(),
            other => other.to_string(),
        }
    }
}

/// A pending authorization request, projected for human review.
///
/// This is the payload behind the approval panel. Every field except `reason`
/// is broker-verified: measured from the page context, resolved from the
/// credential store, or decided by the policy evaluator. `reason` is the
/// agent's own words and is tagged as such.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiAuthorizationRequest {
    pub approval_id: String,
    pub request_id: String,
    /// Agent display name. Untrusted at enrollment time but fixed thereafter;
    /// the UI still length-clamps it.
    pub agent_name: String,
    pub agent_id: String,
    /// Credential *name*, never its provider locator.
    pub credential_name: String,
    /// Provider holding the secret, e.g. "macOS Keychain".
    pub provider: String,
    /// Canonical origin measured from the live page, not claimed by the agent.
    pub origin: String,
    pub action: ActionKind,
    /// Human phrasing of `action`, e.g. "Sign in".
    pub action_label: String,
    pub flow_steps: Vec<UiFlowStep>,
    pub risk: RiskLevel,
    /// Agent-supplied justification. Always paired with `reason_source`.
    pub reason: Option<String>,
    pub reason_source: ReasonSource,
    /// Base64url of the digest the human is approving. The UI echoes this back
    /// on decide so the daemon can confirm the page has not navigated since.
    pub context_digest: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Whether this decision demands live user presence.
    pub requires_presence: bool,
    /// True when this agent has no prior approved request, so the UI can show
    /// the first-authorization framing.
    pub is_first_for_agent: bool,
    /// Whether a standing authorization could cover this tuple. False when the
    /// evaluated risk exceeds `MAX_GRANTABLE_RISK` or presence is mandatory.
    pub grantable: bool,
}

/// Overall protection state, driving the menu-bar icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiProtectionState {
    /// Daemon healthy, nothing in flight.
    Protected,
    /// At least one request is waiting on a human.
    ApprovalRequired,
    /// A capability is being consumed right now.
    SensitiveOperation,
    /// A sensitive operation finished successfully; transient.
    Completed,
    /// A request was denied or a check failed closed.
    Blocked,
    /// Browser protection could not be verified mid-operation. Fail-closed.
    ProtectionInterrupted,
    /// The outcome of an operation could not be confirmed either way.
    OutcomeUncertain,
    /// The daemon is unreachable. All sensitive operations are disabled.
    Disconnected,
}

/// A credential operation currently in flight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiActiveOperation {
    pub request_id: String,
    pub agent_name: String,
    pub credential_name: String,
    pub origin: String,
    pub action_label: String,
    /// Flow steps with per-step completion, for the progress list.
    pub steps: Vec<UiOperationStep>,
    /// Protections the executor has *actually* confirmed. Never populated from
    /// UI-side assumptions.
    pub confirmed_protections: Vec<String>,
    /// Whether the broker still holds a live heartbeat from the executor.
    pub protection_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiStepState {
    Pending,
    Active,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiOperationStep {
    pub label: String,
    pub state: UiStepState,
}

/// Snapshot powering the popover header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiStatus {
    pub protection: UiProtectionState,
    pub pending_approvals: u32,
    pub active_operation: Option<UiActiveOperation>,
    pub browser_sessions_connected: u32,
    pub agents_enrolled: u32,
    pub agents_active: u32,
    pub active_grants: u32,
    /// Distinct provider names backing enrolled credentials.
    pub providers: Vec<String>,
    /// Short policy fingerprint, for the diagnostics pane.
    pub policy_fingerprint: String,
    /// Whether the append-only audit chain verified on last check.
    pub audit_chain_intact: bool,
}

/// A standing authorization, projected for the grants list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiGrant {
    pub grant_id: String,
    pub agent_name: String,
    pub credential_name: String,
    pub origin: String,
    pub action: ActionKind,
    pub action_label: String,
    pub risk_ceiling: RiskLevel,
    pub require_presence: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_reason: Option<String>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub use_count: u64,
    pub active: bool,
}

/// An enrolled agent, projected for the agents list. The agent's public key is
/// deliberately omitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiAgent {
    pub agent_id: String,
    pub display_name: String,
    pub role: String,
    pub state: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub active_grants: u32,
    pub recent_event_count: u32,
    pub last_activity_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A credential *reference*. Carries no secret and no provider locator, so the
/// credentials screen can never become a password manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiCredential {
    pub name: String,
    pub kind: String,
    pub provider: String,
    pub allowed_actions: Vec<ActionKind>,
    pub approved_origins: Vec<String>,
    pub used_by: Vec<String>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub disabled: bool,
}

/// A managed browser session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiBrowserSession {
    pub session_id: String,
    pub profile: String,
    pub state: String,
    pub assurance: String,
    pub last_heartbeat_at: chrono::DateTime<chrono::Utc>,
    pub active_tab_count: u32,
    /// Origins currently observed in this session's measured page contexts.
    pub current_origins: Vec<String>,
}

/// Outcome classification for an activity row, so the UI never has to parse
/// event type strings itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiEventOutcome {
    Success,
    Denied,
    Pending,
    Interrupted,
    Info,
}

/// One audit event, projected for the activity list. `event_json` is not
/// forwarded: it is an internal shape and is not needed to render a row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiActivityEvent {
    pub sequence: u64,
    pub event_id: String,
    pub event_type: String,
    /// Human summary, e.g. "GitHub authentication".
    pub summary: String,
    pub outcome: UiEventOutcome,
    pub actor_type: String,
    pub actor_name: Option<String>,
    pub origin: Option<String>,
    pub action: Option<ActionKind>,
    pub risk: Option<RiskLevel>,
    /// Machine error code, shown only behind "technical details".
    pub error_code: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Human label for an action kind, used in every UI surface.
pub fn action_label(action: ActionKind) -> &'static str {
    match action {
        ActionKind::AuthenticatePassword => "Sign in",
        ActionKind::AuthenticateTotp => "Complete TOTP",
        ActionKind::FormSensitiveFill => "Fill sensitive form",
        ActionKind::OAuthAuthorize => "Authorize OAuth access",
    }
}

// ---------------------------------------------------------------------------
// Admin RPC parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecideParams {
    pub approval_id: ApprovalId,
    /// `approve` or `deny`.
    pub decision: String,
    pub context_digest: Vec<u8>,
    #[serde(default)]
    pub presence_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiActivityParams {
    #[serde(default = "default_activity_limit")]
    pub limit: u32,
}

fn default_activity_limit() -> u32 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantListParams {
    #[serde(default)]
    pub include_revoked: bool,
}

/// Create a standing authorization *from a pending approval*, and approve that
/// approval in the same call.
///
/// Taking the approval id rather than a free-form tuple is deliberate: it means
/// the UI cannot mint a grant for an (agent, credential, origin, action) the
/// broker has not just independently verified against a live page.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCreateParams {
    pub approval_id: ApprovalId,
    /// Echoed digest, same contract as `approval.decide`.
    pub context_digest: Vec<u8>,
    pub ttl_days: i64,
    #[serde(default)]
    pub presence_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantCreateResult {
    pub grant: UiGrant,
    pub decision: crate::ActionResponseResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRevokeParams {
    /// Grant id, or `agent:<name>` / `credential:<name>` for a bulk revoke.
    pub selector: String,
    #[serde(default = "default_revoke_reason")]
    pub reason: String,
}

fn default_revoke_reason() -> String {
    "revoked by user".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRevokeResult {
    pub revoked: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDisableParams {
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityListParams {
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRevokeParams {
    pub capability_id: CapabilityId,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReloadParams {
    pub policy_yaml: String,
    pub expected_hash: String,
}

#[cfg(test)]
mod admin_dto_tests {
    use super::*;

    /// Field names that must never appear anywhere in a UI-bound payload.
    ///
    /// This is the mechanical form of the module's contract. It runs over the
    /// serialized JSON, so it catches a secret-bearing field added to any
    /// nested type, not just the top level.
    const FORBIDDEN_KEYS: &[&str] = &[
        "password",
        "secret",
        "token",
        "token_hash",
        "provider_locator",
        "locator",
        "public_key",
        "private_key",
        "seed",
        "otp",
        "api_key",
        "access_token",
        "credential_bytes",
        "value",
        "event_json",
    ];

    fn assert_no_forbidden_keys(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    assert!(
                        !FORBIDDEN_KEYS.contains(&key.as_str()),
                        "UI DTO exposes forbidden field '{key}' at {path}"
                    );
                    assert_no_forbidden_keys(child, &format!("{path}.{key}"));
                }
            }
            serde_json::Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    assert_no_forbidden_keys(child, &format!("{path}[{index}]"));
                }
            }
            _ => {}
        }
    }

    fn sample_request() -> UiAuthorizationRequest {
        UiAuthorizationRequest {
            approval_id: "apr_1".to_string(),
            request_id: "req_1".to_string(),
            agent_name: "Claude".to_string(),
            agent_id: "agt_1".to_string(),
            credential_name: "github-work".to_string(),
            provider: "macOS Keychain".to_string(),
            origin: "https://github.com:443".to_string(),
            action: ActionKind::AuthenticatePassword,
            action_label: "Sign in".to_string(),
            flow_steps: vec![UiFlowStep {
                role: "password".to_string(),
                label: "Password".to_string(),
                optional: false,
            }],
            risk: RiskLevel::Medium,
            reason: Some("Review open pull requests".to_string()),
            reason_source: ReasonSource::AgentProvided,
            context_digest: "AAAA".to_string(),
            expires_at: chrono::Utc::now(),
            requires_presence: true,
            is_first_for_agent: true,
            grantable: true,
        }
    }

    #[test]
    fn authorization_request_carries_no_secret_bearing_field() {
        let json = serde_json::to_value(sample_request()).unwrap();
        assert_no_forbidden_keys(&json, "UiAuthorizationRequest");
    }

    #[test]
    fn agent_supplied_reason_is_always_tagged_as_such() {
        let request = sample_request();
        assert_eq!(request.reason_source, ReasonSource::AgentProvided);
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["reason_source"], "agent_provided");
    }

    #[test]
    fn credential_reference_never_exposes_where_the_secret_lives() {
        let credential = UiCredential {
            name: "github-work".to_string(),
            kind: "password".to_string(),
            provider: "macOS Keychain".to_string(),
            allowed_actions: vec![ActionKind::AuthenticatePassword],
            approved_origins: vec!["https://github.com:443".to_string()],
            used_by: vec!["Claude".to_string()],
            last_used_at: None,
            disabled: false,
        };
        let json = serde_json::to_value(credential).unwrap();
        assert_no_forbidden_keys(&json, "UiCredential");
        assert!(json.get("provider_locator").is_none());
    }

    #[test]
    fn agent_projection_omits_the_enrollment_public_key() {
        let agent = UiAgent {
            agent_id: "agt_1".to_string(),
            display_name: "Claude".to_string(),
            role: "agent".to_string(),
            state: "enrolled".to_string(),
            created_at: chrono::Utc::now(),
            active_grants: 3,
            recent_event_count: 12,
            last_activity_at: None,
        };
        let json = serde_json::to_value(agent).unwrap();
        assert_no_forbidden_keys(&json, "UiAgent");
    }

    #[test]
    fn activity_event_drops_the_raw_event_body() {
        let event = UiActivityEvent {
            sequence: 7,
            event_id: "evt_1".to_string(),
            event_type: "capability.issued".to_string(),
            summary: "GitHub authentication".to_string(),
            outcome: UiEventOutcome::Success,
            actor_type: "broker".to_string(),
            actor_name: Some("Claude".to_string()),
            origin: Some("https://github.com:443".to_string()),
            action: Some(ActionKind::AuthenticatePassword),
            risk: Some(RiskLevel::Medium),
            error_code: None,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(event).unwrap();
        assert_no_forbidden_keys(&json, "UiActivityEvent");
    }

    #[test]
    fn every_action_kind_has_a_human_label() {
        for action in [
            ActionKind::AuthenticatePassword,
            ActionKind::AuthenticateTotp,
            ActionKind::FormSensitiveFill,
            ActionKind::OAuthAuthorize,
        ] {
            assert!(!action_label(action).is_empty());
            assert_ne!(action_label(action), action.as_str());
        }
    }
}
