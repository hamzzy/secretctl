use crate::error::AuditError;
use secretctl_crypto::contains_prohibited_key_name;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

pub fn validate_audit_payload(json_str: &str) -> Result<(), AuditError> {
    let value: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| AuditError::Serialization(e.to_string()))?;

    if let serde_json::Value::Object(map) = value {
        for (k, _) in map {
            if contains_prohibited_key_name(&k) {
                return Err(AuditError::ProhibitedPayload(k));
            }
        }
    }
    Ok(())
}
