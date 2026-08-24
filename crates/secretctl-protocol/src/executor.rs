use secretctl_domain::{BrowserSessionId, CanonicalOrigin, ExecutionId, RecipeId};
use serde::{Deserialize, Serialize};

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
