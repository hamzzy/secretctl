use crate::actions::ActionKind;
use crate::id::{
    AgentId, ApprovalId, BrowserInstanceId, BrowserSessionId, CapabilityId, CredentialId, EventId,
    ExecutionId, GrantId, RecipeId, RequestId, RuleId,
};
use crate::origin::CanonicalOrigin;
use crate::states::{ActionRequestState, BrowserSessionState, CapabilityState, ExecutionState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPrincipal {
    pub agent_id: AgentId,
    pub public_key: Vec<u8>,
    pub display_name: String,
    pub executable_hash: Option<Vec<u8>>,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    pub credential_id: CredentialId,
    pub name: String,
    pub kind: String,
    pub provider: String,
    pub provider_locator: String,
    pub allowed_actions: Vec<ActionKind>,
    pub metadata_json: String,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeField {
    pub role: String,
    pub selector: String,
    pub optional: bool,
    pub clear_first: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeSubmit {
    pub selector: Option<String>,
    pub auto_submit: bool,
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeSuccessIndicators {
    pub navigation_origin: Option<String>,
    pub selector_present: Option<String>,
    pub selector_absent: Option<String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteRecipe {
    pub recipe_id: RecipeId,
    pub version: u32,
    pub name: String,
    pub action: ActionKind,
    pub top_origin: CanonicalOrigin,
    pub path_prefix: Option<String>,
    pub frame_origin: Option<CanonicalOrigin>,
    pub fields: Vec<RecipeField>,
    pub submit: Option<RecipeSubmit>,
    pub success_indicators: Option<RecipeSuccessIndicators>,
    pub content_hash: Vec<u8>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInstance {
    pub instance_id: BrowserInstanceId,
    pub launcher_nonce: String,
    pub binary_hash: Option<Vec<u8>>,
    pub extension_key_id: String,
    pub private_cdp_endpoint: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    pub session_id: BrowserSessionId,
    pub instance_id: BrowserInstanceId,
    pub extension_key_id: String,
    pub profile_id: String,
    pub assurance: String,
    pub state: BrowserSessionState,
    pub last_heartbeat_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageContext {
    pub tab_id: u32,
    pub frame_id: u32,
    pub top_origin: CanonicalOrigin,
    pub frame_origin: CanonicalOrigin,
    pub navigation_epoch: u64,
    pub document_id: String,
    pub path_sha256: String,
    pub tls: bool,
    pub incognito: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub credential_id: CredentialId,
    pub action: ActionKind,
    pub target_origin: CanonicalOrigin,
    pub path_prefix: Option<String>,
    pub browser_session_id: BrowserSessionId,
    pub tab_hint: Option<u32>,
    pub reason: String,
    pub state: ActionRequestState,
    pub policy_hash: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    pub risk_level: RiskLevel,
    pub rule_id: Option<RuleId>,
    pub policy_hash: Vec<u8>,
    pub require_user_presence: bool,
    pub max_uses: u32,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approval_id: ApprovalId,
    pub request_id: RequestId,
    pub decision: String,
    pub actor: Option<String>,
    pub presence: Option<String>,
    pub context_digest: Vec<u8>,
    pub decided_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub capability_id: CapabilityId,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub credential_id: CredentialId,
    pub action: ActionKind,
    pub top_origin: CanonicalOrigin,
    pub frame_origin: CanonicalOrigin,
    pub browser_session_id: BrowserSessionId,
    pub extension_key_id: String,
    pub tab_id: u32,
    pub frame_id: u32,
    pub document_id: String,
    pub navigation_epoch: u64,
    pub recipe_id: RecipeId,
    pub recipe_hash: Vec<u8>,
    pub policy_hash: Vec<u8>,
    pub token_hash: Vec<u8>,
    pub state: CapabilityState,
    pub max_uses: u32,
    pub used_count: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_reason: Option<String>,
}

impl Capability {
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        (self.state == CapabilityState::Issued || self.state == CapabilityState::Active)
            && now <= self.expires_at
            && self.used_count < self.max_uses
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    pub execution_id: ExecutionId,
    pub capability_id: CapabilityId,
    pub state: ExecutionState,
    pub prepared_context_digest: Option<Vec<u8>>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthGrant {
    pub grant_id: GrantId,
    pub credential_id: CredentialId,
    pub provider_locator: String,
    pub scopes: Vec<String>,
    pub subject_hint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub event_id: EventId,
    pub event_type: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub event_json: String,
    pub previous_hash: Vec<u8>,
    pub event_hash: Vec<u8>,
    pub created_at: DateTime<Utc>,
}
