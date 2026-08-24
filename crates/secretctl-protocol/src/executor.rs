use secretctl_domain::{
    BrowserInstanceId, BrowserSessionId, CanonicalOrigin, ExecutionId, GrantId, RecipeId,
};
use serde::{Deserialize, Serialize};

/// ID derived from the public key pinned in the packaged MV3 manifest.
pub const MANAGED_EXTENSION_ID: &str = "kepjngjifdbhbohpljaehekkkjdpecli";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorContextPayload {
    pub browser_session_id: BrowserSessionId,
    pub tab_id: u32,
    pub frame_id: u32,
    pub document_id: String,
    pub navigation_epoch: u64,
    pub top_origin: CanonicalOrigin,
    pub frame_origin: CanonicalOrigin,
    pub path: String,
    pub path_sha256: String,
    pub tls: bool,
    #[serde(default)]
    pub incognito: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorPrepareParams {
    pub context: ExecutorContextPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorPrepareResult {
    pub prepared: bool,
    pub challenge_nonce: String,
    pub matching_recipes: Vec<RecipeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRegisterParams {
    pub instance_id: BrowserInstanceId,
    pub launcher_nonce: String,
    pub profile_id: String,
    pub extension_id: String,
    pub extension_version: String,
    pub extension_key_id: String,
    pub browser_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserRegisterResult {
    pub browser_session_id: BrowserSessionId,
    pub assurance: String,
    pub heartbeat_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionNextParams {
    pub browser_session_id: BrowserSessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionFieldPlan {
    pub role: String,
    pub selector: String,
    pub optional: bool,
    pub clear_first: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOfferResult {
    pub capability_token: String,
    pub recipe_id: RecipeId,
    pub tab_id: u32,
    pub frame_id: u32,
    pub document_id: String,
    pub navigation_epoch: u64,
    pub top_origin: CanonicalOrigin,
    pub frame_origin: CanonicalOrigin,
    pub fields: Vec<ExecutionFieldPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_submit_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<ExecutionSuccessPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthExecutionPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthExecutionPlan {
    pub authorization_url: String,
    pub issuer_origin: CanonicalOrigin,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthCallbackParams {
    pub capability_token: String,
    pub browser_session_id: BrowserSessionId,
    pub tab_id: u32,
    pub callback_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCallbackResult {
    pub grant_id: GrantId,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSuccessPlan {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub navigation_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_present: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_absent: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionNextResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer: Option<ExecutionOfferResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorConsumeParams {
    pub capability_token: String,
    pub session_signature: String,
    pub current_context: ExecutorContextPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedFieldInjection {
    pub role: String,
    pub selector: String,
    pub optional: bool,
    pub clear_first: bool,
    pub encrypted_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorConsumeResult {
    pub execution_id: ExecutionId,
    pub recipe_id: RecipeId,
    pub fields: Vec<ResolvedFieldInjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_submit_selector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvidence {
    #[serde(default)]
    pub submitted: bool,
    pub fields_filled_count: u32,
    #[serde(default)]
    pub outcome_selector_matched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorResultParams {
    pub execution_id: ExecutionId,
    pub status: String,
    pub result_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ExecutionEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorResultResult {
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorHeartbeatParams {
    pub browser_session_id: BrowserSessionId,
    pub active_tab_count: u32,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorHeartbeatResult {
    pub acknowledged: bool,
}
