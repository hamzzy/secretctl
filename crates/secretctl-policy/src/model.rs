use secretctl_domain::{ActionKind, CanonicalOrigin, PolicyEffect, RuleId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationRule {
    pub origin: CanonicalOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleConditions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_assurance: Option<String>,
    #[serde(default)]
    pub require_user_presence: bool,
    #[serde(default = "default_max_uses")]
    pub max_uses: u32,
    /// Ceiling on the secret-release window. Kept short; this is not how long
    /// the login may take.
    #[serde(default = "default_max_consume_ttl", alias = "max_ttl_seconds")]
    pub max_consume_ttl_seconds: u64,
    /// Ceiling on how long the action may take once the secret has been
    /// released. Separate from the consume window by design (see
    /// `PolicyDecision`).
    #[serde(default = "default_max_execution_ttl")]
    pub max_execution_ttl_seconds: u64,
}

fn default_max_uses() -> u32 {
    1
}

fn default_max_consume_ttl() -> u64 {
    30
}

fn default_max_execution_ttl() -> u64 {
    secretctl_domain::DEFAULT_EXECUTION_TTL_SECONDS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: RuleId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub effect: PolicyEffect,
    pub principals: Vec<String>,
    pub credentials: Vec<String>,
    pub actions: Vec<ActionKind>,
    pub destinations: Vec<DestinationRule>,
    #[serde(default)]
    pub conditions: RuleConditions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub version: String,
    pub rules: Vec<PolicyRule>,
}

impl PolicyDocument {
    pub fn from_yaml(yaml_str: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml_str)
    }

    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}
