use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalChannel {
    Agent,
    Admin,
    Executor,
}

impl LocalChannel {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Admin => "admin",
            Self::Executor => "executor",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEndpoint {
    UnixSocket(PathBuf),
    WindowsNamedPipe(String),
}

pub fn unix_endpoint(runtime_dir: &Path, channel: LocalChannel) -> LocalEndpoint {
    LocalEndpoint::UnixSocket(runtime_dir.join(format!("{}.sock", channel.name())))
}

pub fn windows_endpoint(installation_id: &str, channel: LocalChannel) -> LocalEndpoint {
    let safe_installation_id: String = installation_id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect();
    LocalEndpoint::WindowsNamedPipe(format!(
        r"\\.\pipe\secretctl-{}-{}",
        safe_installation_id,
        channel.name()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_endpoints_keep_channels_separate() {
        assert_eq!(
            unix_endpoint(Path::new("/run/secretctl"), LocalChannel::Executor),
            LocalEndpoint::UnixSocket(PathBuf::from("/run/secretctl/executor.sock"))
        );
        assert_eq!(
            windows_endpoint("inst_01-test", LocalChannel::Admin),
            LocalEndpoint::WindowsNamedPipe(r"\\.\pipe\secretctl-inst01-test-admin".to_string())
        );
    }
}
