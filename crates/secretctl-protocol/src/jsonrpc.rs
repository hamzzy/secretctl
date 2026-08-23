use crate::error::RpcError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcId {
    String(String),
    Number(i64),
    Null,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest<P = serde_json::Value> {
    pub jsonrpc: String,
    pub id: RpcId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<P>,
}

impl<P> RpcRequest<P> {
    pub fn new(id: impl Into<String>, method: impl Into<String>, params: Option<P>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: RpcId::String(id.into()),
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse<R = serde_json::Value> {
    pub jsonrpc: String,
    pub id: RpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<R>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl<R> RpcResponse<R> {
    pub fn success(id: RpcId, result: R) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: RpcId, error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNotification<P = serde_json::Value> {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<P>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_request_serialization() {
        let req = RpcRequest::new("rpc_1", "action.request", Some(serde_json::json!({})));
        let json_str = serde_json::to_string(&req).unwrap();
        assert!(json_str.contains("\"jsonrpc\":\"2.0\""));
        assert!(json_str.contains("\"method\":\"action.request\""));
    }
}
