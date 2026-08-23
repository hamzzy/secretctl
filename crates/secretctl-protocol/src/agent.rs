use secretctl_domain::{
    ActionKind, ActionRequestState, BrowserSessionId, CanonicalOrigin, ExecutionId, RequestId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetOriginConstraint {
    pub origin: CanonicalOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequestParams {
    pub request_id: RequestId,
    pub action: ActionKind,
    pub identity: String,
    pub target: TargetOriginConstraint,
    pub browser_session_id: BrowserSessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tab_hint: Option<u32>,
    pub reason: String,
    #[serde(default = "default_true")]
    pub wait: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_context: Option<serde_json::Value>,
}

fn default_true() -> bool {
    true
}

fn default_timeout_ms() -> u64 {
    60000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResponseResult {
    pub request_id: RequestId,
    pub state: ActionRequestState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStatusParams {
    pub request_id: RequestId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStatusResult {
    pub request_id: RequestId,
    pub state: ActionRequestState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCancelParams {
    pub request_id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCancelResult {
    pub request_id: RequestId,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserRequestSessionParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default)]
    pub incognito: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserRequestSessionResult {
    pub browser_session_id: BrowserSessionId,
    pub gateway_endpoint: String,
    pub assurance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHelloParams {
    pub protocol_version: String,
    pub role: String,
    pub principal_id: String,
    pub client_nonce: String,
    pub supported_suites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHelloResult {
    pub protocol_version: String,
    pub server_nonce: String,
    pub ephemeral_public_key: String,
    pub server_key_id: String,
    pub signature: String,
}
