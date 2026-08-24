use crate::error::DomainError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident, $prefix:expr) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(format!("{}_{}", $prefix, Uuid::now_v7()))
            }

            pub fn parse(s: &str) -> Result<Self, DomainError> {
                if !s.starts_with(concat!($prefix, "_")) || s.len() <= $prefix.len() + 1 {
                    return Err(DomainError::InvalidId(format!(
                        "Expected prefix '{}', got '{}'",
                        $prefix, s
                    )));
                }
                Ok(Self(s.to_string()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }
    };
}

define_id!(AgentId, "agent");
define_id!(CredentialId, "cred");
define_id!(RecipeId, "rcp");
define_id!(BrowserInstanceId, "bi");
define_id!(BrowserSessionId, "bs");
define_id!(CapabilityId, "cap");
define_id!(RequestId, "req");
define_id!(ApprovalId, "app");
define_id!(ExecutionId, "exec");
define_id!(GrantId, "grant");
define_id!(EventId, "evt");
define_id!(RuleId, "rule");
define_id!(FlowId, "flw");
define_id!(FlowStepId, "stp");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_generation_and_parsing() {
        let agent_id = AgentId::new();
        assert!(agent_id.as_str().starts_with("agent_"));

        let parsed = AgentId::parse(agent_id.as_str()).expect("should parse valid id");
        assert_eq!(agent_id, parsed);

        assert!(AgentId::parse("invalid_id").is_err());
        assert!(AgentId::parse("agent_").is_err());
    }
}
