use secretctl_domain::{ActionKind, RiskLevel};

pub fn calculate_risk_level(
    action: ActionKind,
    require_user_presence: bool,
    browser_assurance: &str,
) -> RiskLevel {
    if browser_assurance != "managed" {
        return RiskLevel::Critical;
    }

    if require_user_presence {
        return RiskLevel::High;
    }

    match action {
        ActionKind::AuthenticatePassword => RiskLevel::Medium,
        ActionKind::AuthenticateTotp => RiskLevel::Medium,
        ActionKind::FormSensitiveFill => RiskLevel::High,
        ActionKind::OAuthAuthorize => RiskLevel::Low,
    }
}
