use secretctl_domain::RiskLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    Macos,
    Windows,
    Linux,
}

pub fn current_platform() -> HostPlatform {
    #[cfg(target_os = "macos")]
    {
        HostPlatform::Macos
    }
    #[cfg(target_os = "windows")]
    {
        HostPlatform::Windows
    }
    #[cfg(target_os = "linux")]
    {
        HostPlatform::Linux
    }
}

/// Linux V1 has no portable trusted local-user/biometric presence mechanism.
/// High and critical actions therefore fail instead of degrading to confirm.
pub fn assurance_available(platform: HostPlatform, risk: RiskLevel) -> bool {
    platform != HostPlatform::Linux || matches!(risk, RiskLevel::Low | RiskLevel::Medium)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_high_risk_never_silently_downgrades() {
        assert!(!assurance_available(HostPlatform::Linux, RiskLevel::High));
        assert!(!assurance_available(
            HostPlatform::Linux,
            RiskLevel::Critical
        ));
        assert!(assurance_available(HostPlatform::Linux, RiskLevel::Medium));
        assert!(assurance_available(HostPlatform::Macos, RiskLevel::High));
        assert!(assurance_available(HostPlatform::Windows, RiskLevel::High));
    }
}
