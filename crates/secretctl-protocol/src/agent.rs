use secretctl_domain::{
    ActionKind, ActionRequestState, BrowserSessionId, CanonicalOrigin, ExecutionId, RequestId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetOriginConstraint {
    pub origin: CanonicalOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ActionAuthenticateParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionKind>,
    pub identity: String,
    pub reason: String,
    #[serde(default = "default_true")]
    pub wait: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_context: Option<serde_json::Value>,
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
    pub grant_id: Option<secretctl_domain::GrantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAuthenticateResult {
    #[serde(flatten)]
    pub response: ActionResponseResult,
    pub action: ActionKind,
    pub verified_origin: CanonicalOrigin,
    pub browser_session_id: BrowserSessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionStatusParams {
    pub request_id: RequestId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSubscribeParams {
    pub request_id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_state: Option<ActionRequestState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_detail: Option<String>,
    #[serde(default = "default_subscribe_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_subscribe_timeout_ms() -> u64 {
    30_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStatusResult {
    pub request_id: RequestId,
    pub state: ActionRequestState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAuthenticateParams {
    pub client_ephemeral_public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAuthenticateResult {
    pub authenticated: bool,
    pub rekey_after_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfoResult {
    pub protocol_version: String,
    pub principal_id: String,
    pub role: String,
    pub rekey_after_seconds: u64,
}

pub fn session_auth_transcript(
    hello: &SessionHelloParams,
    server_nonce: &str,
    server_ephemeral_public_key: &[u8; 32],
    client_ephemeral_public_key: &[u8; 32],
) -> [u8; 32] {
    secretctl_crypto::compute_context_digest(&[
        b"secretctl-session-auth-v1",
        hello.protocol_version.as_bytes(),
        hello.role.as_bytes(),
        hello.principal_id.as_bytes(),
        hello.client_nonce.as_bytes(),
        server_nonce.as_bytes(),
        server_ephemeral_public_key,
        client_ephemeral_public_key,
    ])
}
