use crate::error::GatewayError;
use chrono::Utc;
use secretctl_domain::{BrowserInstance, BrowserInstanceId};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use uuid::Uuid;

pub struct LaunchedBrowser {
    pub instance: BrowserInstance,
    pub profile_dir: PathBuf,
    pub process: Option<Child>,
}

pub struct BrowserLauncher {
    chrome_binary_path: PathBuf,
    extension_path: PathBuf,
}

impl BrowserLauncher {
    pub fn new(chrome_binary_path: impl AsRef<Path>, extension_path: impl AsRef<Path>) -> Self {
        Self {
            chrome_binary_path: chrome_binary_path.as_ref().to_path_buf(),
            extension_path: extension_path.as_ref().to_path_buf(),
        }
    }

    pub fn find_default_chrome_binary() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            let mac_path =
                PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
            if mac_path.exists() {
                return mac_path;
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(path) = which::which("google-chrome") {
                return path;
            }
            if let Ok(path) = which::which("chromium") {
                return path;
            }
        }

        PathBuf::from("google-chrome")
    }

    pub fn launch(
        &self,
        custom_profile_dir: Option<PathBuf>,
        mock_mode: bool,
    ) -> Result<LaunchedBrowser, GatewayError> {
        let instance_id = BrowserInstanceId::new();
        let launcher_nonce = Uuid::new_v4().to_string();

        let profile_dir = match custom_profile_dir {
            Some(p) => p,
            None => {
                let temp_dir =
                    std::env::temp_dir().join(format!("secretctl_browser_{}", instance_id));
                std::fs::create_dir_all(&temp_dir)?;
                temp_dir
            }
        };

        let instance = BrowserInstance {
            instance_id,
            launcher_nonce,
            binary_hash: None,
            extension_key_id: "ext-packaged-key".to_string(),
            private_cdp_endpoint: "pipe:0".to_string(),
            created_at: Utc::now(),
        };

        if mock_mode {
            return Ok(LaunchedBrowser {
                instance,
                profile_dir,
                process: None,
            });
        }

        let mut cmd = Command::new(&self.chrome_binary_path);
        cmd.arg(format!("--user-data-dir={}", profile_dir.display()))
            .arg(format!(
                "--load-extension={}",
                self.extension_path.display()
            ))
            .arg(format!(
                "--disable-extensions-except={}",
                self.extension_path.display()
            ))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--remote-debugging-pipe");

        let child = cmd.spawn().map_err(|e| {
            GatewayError::LaunchFailed(format!("Failed to spawn Chrome process: {}", e))
        })?;

        Ok(LaunchedBrowser {
            instance,
            profile_dir,
            process: Some(child),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_launcher_mock_mode() {
        let launcher = BrowserLauncher::new("/dummy/chrome", "/dummy/extension");
        let launched = launcher.launch(None, true).expect("mock launch");
        assert!(launched.instance.instance_id.to_string().starts_with("bi_"));
        assert!(launched.profile_dir.exists());
    }
}
