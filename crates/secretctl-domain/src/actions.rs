use crate::error::DomainError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionKind {
    #[serde(rename = "authenticate.password")]
    AuthenticatePassword,
    #[serde(rename = "authenticate.totp")]
    AuthenticateTotp,
    #[serde(rename = "form.sensitive_fill")]
    FormSensitiveFill,
    #[serde(rename = "oauth.authorize")]
    OAuthAuthorize,
}

impl ActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthenticatePassword => "authenticate.password",
            Self::AuthenticateTotp => "authenticate.totp",
            Self::FormSensitiveFill => "form.sensitive_fill",
            Self::OAuthAuthorize => "oauth.authorize",
        }
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ActionKind {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authenticate.password" => Ok(Self::AuthenticatePassword),
            "authenticate.totp" => Ok(Self::AuthenticateTotp),
            "form.sensitive_fill" => Ok(Self::FormSensitiveFill),
            "oauth.authorize" => Ok(Self::OAuthAuthorize),
            _ => Err(DomainError::InvalidAction(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_serialization_and_parsing() {
        let action = ActionKind::AuthenticatePassword;
        let serialized = serde_json::to_string(&action).unwrap();
        assert_eq!(serialized, "\"authenticate.password\"");

        let parsed: ActionKind = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, ActionKind::AuthenticatePassword);

        let from_str = ActionKind::from_str("authenticate.totp").unwrap();
        assert_eq!(from_str, ActionKind::AuthenticateTotp);

        assert!(ActionKind::from_str("arbitrary.action").is_err());
    }
}
