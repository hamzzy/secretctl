use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Framing error: {0}")]
    Framing(String),

    #[error("Message exceeded maximum size: limit {limit}, actual {actual}")]
    MessageTooLarge { limit: usize, actual: usize },

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Prohibited secret-bearing field detected in payload: {0}")]
    ProhibitedField(String),

    #[error("Protocol version mismatch: {0}")]
    VersionMismatch(String),

    #[error("Invalid JSON-RPC format: {0}")]
    InvalidRpc(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcErrorCode(pub i32);

impl RpcErrorCode {
    // JSON-RPC 2.0 Standard Errors
    pub const PARSE_ERROR: RpcErrorCode = RpcErrorCode(-32700);
    pub const INVALID_REQUEST: RpcErrorCode = RpcErrorCode(-32600);
    pub const METHOD_NOT_FOUND: RpcErrorCode = RpcErrorCode(-32601);
    pub const INVALID_PARAMS: RpcErrorCode = RpcErrorCode(-32602);
    pub const INTERNAL_ERROR: RpcErrorCode = RpcErrorCode(-32603);

    // secretctl Specific Errors
    pub const AUTH_POLICY_DENIED: RpcErrorCode = RpcErrorCode(-32001);
    pub const APPROVAL_REJECTED: RpcErrorCode = RpcErrorCode(-32002);
    pub const APPROVAL_TIMEOUT: RpcErrorCode = RpcErrorCode(-32003);
    pub const CAPABILITY_EXPIRED: RpcErrorCode = RpcErrorCode(-32004);
    pub const CAPABILITY_CONSUMED: RpcErrorCode = RpcErrorCode(-32005);
    pub const EPOCH_INVALIDATED: RpcErrorCode = RpcErrorCode(-32006);
    pub const ORIGIN_MISMATCH: RpcErrorCode = RpcErrorCode(-32007);
    pub const FRAME_VIOLATION: RpcErrorCode = RpcErrorCode(-32008);
    pub const SESSION_TERMINATED: RpcErrorCode = RpcErrorCode(-32009);
    pub const EXECUTOR_FAILED: RpcErrorCode = RpcErrorCode(-32010);
    pub const RECIPE_NOT_FOUND: RpcErrorCode = RpcErrorCode(-32011);
    pub const USER_PRESENCE_UNAVAILABLE: RpcErrorCode = RpcErrorCode(-32012);
    pub const SECURITY_VIOLATION: RpcErrorCode = RpcErrorCode(-32099);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl RpcError {
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.0,
            message: message.into(),
            data: None,
        }
    }
}
