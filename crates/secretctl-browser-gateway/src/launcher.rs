use crate::CdpPipe;
use crate::error::GatewayError;
use chrono::Utc;
#[cfg(unix)]
use command_fds::{CommandFdExt, FdMapping};
use secretctl_domain::{BrowserInstance, BrowserInstanceId};
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader};
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub struct LaunchedBrowser {
    pub instance: BrowserInstance,
    pub profile_dir: PathBuf,
    pub process: Option<Child>,
    pub cdp_pipe: Option<CdpPipe>,
    pub startup_diagnostics: Arc<Mutex<Vec<String>>>,
}

pub struct BrowserLauncher {
    chrome_binary_path: PathBuf,
    extension_path: PathBuf,
    native_host_binary_path: Option<PathBuf>,
    headless: bool,
}

impl BrowserLauncher {
    pub fn new(chrome_binary_path: impl AsRef<Path>, extension_path: impl AsRef<Path>) -> Self {
        Self {
            chrome_binary_path: chrome_binary_path.as_ref().to_path_buf(),
            extension_path: extension_path.as_ref().to_path_buf(),
            native_host_binary_path: None,
            headless: false,
        }
    }

    pub fn native_host(mut self, native_host_binary_path: impl AsRef<Path>) -> Self {
        self.native_host_binary_path = Some(native_host_binary_path.as_ref().to_path_buf());
        self
    }

    pub fn headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
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
        std::fs::create_dir_all(&profile_dir)?;
        #[cfg(unix)]
        {
            std::fs::set_permissions(&profile_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        if !mock_mode {
            let native_host_binary = self
                .native_host_binary_path
                .as_ref()
                .ok_or_else(|| {
                    GatewayError::LaunchFailed("Native host binary was not configured".to_string())
                })?
                .canonicalize()
                .map_err(|error| {
                    GatewayError::LaunchFailed(format!(
                        "Native host binary cannot be resolved: {error}"
                    ))
                })?;
            let native_manifest_dir = profile_dir.join("NativeMessagingHosts");
            std::fs::create_dir_all(&native_manifest_dir)?;
            #[cfg(unix)]
            std::fs::set_permissions(&native_manifest_dir, std::fs::Permissions::from_mode(0o700))?;
            let native_manifest_path = native_manifest_dir.join("com.secretctl.native_host.json");
            let native_manifest = serde_json::json!({
                "name": "com.secretctl.native_host",
                "description": "secretctl Chrome Native Messaging Host",
                "path": native_host_binary,
                "type": "stdio",
                "allowed_origins": [format!(
                    "chrome-extension://{}/",
                    secretctl_protocol::MANAGED_EXTENSION_ID
                )]
            });
            std::fs::write(
                &native_manifest_path,
                serde_json::to_vec_pretty(&native_manifest)?,
            )?;
            #[cfg(unix)]
            std::fs::set_permissions(
                &native_manifest_path,
                std::fs::Permissions::from_mode(0o600),
            )?;
        }

        let binary_hash = if mock_mode {
            None
        } else {
            let mut binary = File::open(&self.chrome_binary_path).map_err(|error| {
                GatewayError::LaunchFailed(format!("Chrome binary is unavailable: {error}"))
            })?;
            let mut bytes = Vec::new();
            binary.read_to_end(&mut bytes)?;
            Some(secretctl_crypto::sha256_digest(&bytes).to_vec())
        };

        let instance = BrowserInstance {
            instance_id,
            launcher_nonce,
            binary_hash,
            extension_key_id: secretctl_protocol::MANAGED_EXTENSION_ID.to_string(),
            private_cdp_endpoint: "pipe:0".to_string(),
            created_at: Utc::now(),
        };

        if mock_mode {
            return Ok(LaunchedBrowser {
                instance,
                profile_dir,
                process: None,
                cdp_pipe: None,
                startup_diagnostics: Arc::new(Mutex::new(Vec::new())),
            });
        }

        if !self.extension_path.join("manifest.json").is_file() {
            return Err(GatewayError::LaunchFailed(
                "Packaged extension directory is missing manifest.json".to_string(),
            ));
        }
        let extension_path = self.extension_path.canonicalize().map_err(|error| {
            GatewayError::LaunchFailed(format!("Extension path cannot be resolved: {error}"))
        })?;

        let mut cmd = Command::new(&self.chrome_binary_path);
        cmd.env(
            "SECRETCTL_BROWSER_INSTANCE_ID",
            instance.instance_id.as_str(),
        )
        .env("SECRETCTL_BROWSER_LAUNCH_NONCE", &instance.launcher_nonce)
        .env(
            "SECRETCTL_BROWSER_PROFILE_ID",
            instance.instance_id.as_str(),
        );
        cmd.arg(format!("--user-data-dir={}", profile_dir.display()))
            .arg("--enable-unsafe-extension-debugging")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--remote-debugging-pipe")
            .arg("--disable-background-networking")
            .arg("--disable-component-update")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        if self.headless {
            cmd.arg("--headless=new");
        }

        #[cfg(unix)]
        let (parent_reader, parent_writer) = {
            let (chrome_read, parent_write) = os_pipe::pipe()?;
            let (parent_read, chrome_write) = os_pipe::pipe()?;
            let chrome_read: OwnedFd = chrome_read.into();
            let chrome_write: OwnedFd = chrome_write.into();
            cmd.fd_mappings(vec![
                FdMapping {
                    parent_fd: chrome_read,
                    child_fd: 3,
                },
                FdMapping {
                    parent_fd: chrome_write,
                    child_fd: 4,
                },
            ])
            .map_err(|error| GatewayError::LaunchFailed(error.to_string()))?;
            (parent_read, parent_write)
        };

        let mut child = cmd.spawn().map_err(|e| {
            GatewayError::LaunchFailed(format!("Failed to spawn Chrome process: {}", e))
        })?;
        let diagnostics = Arc::new(Mutex::new(Vec::new()));
        if let Some(stderr) = child.stderr.take() {
            let diagnostics_sink = diagnostics.clone();
            let profile_display = profile_dir.to_string_lossy().into_owned();
            std::thread::spawn(move || {
                for line in BufReader::new(stderr)
                    .lines()
                    .map_while(Result::ok)
                    .take(100)
                {
                    let sanitized = line
                        .replace(&profile_display, "[managed-profile]")
                        .chars()
                        .take(500)
                        .collect::<String>();
                    diagnostics_sink.lock().unwrap().push(sanitized);
                }
            });
        }

        #[cfg(unix)]
        let cdp_pipe = CdpPipe::new(parent_reader, parent_writer);
        #[cfg(unix)]
        {
            let filter = crate::CdpFilter::new();
            let load_result = cdp_pipe.request(
                &filter,
                "Extensions.loadUnpacked",
                None,
                serde_json::json!({ "path": extension_path }),
            );
            let loaded_id = match load_result {
                Ok(result) => result
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(GatewayError::LaunchFailed(format!(
                        "Chrome could not load the managed extension: {error}"
                    )));
                }
            };
            if loaded_id.as_deref() != Some(secretctl_protocol::MANAGED_EXTENSION_ID) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(GatewayError::LaunchFailed(
                    "Chrome loaded an extension with an unexpected identity".to_string(),
                ));
            }

            let installed = cdp_pipe.request(
                &filter,
                "Extensions.getExtensions",
                None,
                serde_json::json!({}),
            )?;
            let approved = installed
                .get("extensions")
                .and_then(serde_json::Value::as_array)
                .filter(|extensions| extensions.len() == 1)
                .and_then(|extensions| extensions.first())
                .is_some_and(|extension| {
                    extension.get("id").and_then(serde_json::Value::as_str)
                        == Some(secretctl_protocol::MANAGED_EXTENSION_ID)
                        && extension.get("version").and_then(serde_json::Value::as_str)
                            == Some("1.0.0")
                        && extension
                            .get("enabled")
                            .and_then(serde_json::Value::as_bool)
                            == Some(true)
                });
            if !approved {
                let _ = child.kill();
                let _ = child.wait();
                return Err(GatewayError::LaunchFailed(
                    "Managed extension verification failed".to_string(),
                ));
            }
        }

        tracing::info!(
            instance_id = %instance.instance_id,
            profile = %profile_dir.display(),
            "launched managed Chrome with private CDP pipe"
        );
        Ok(LaunchedBrowser {
            instance,
            profile_dir,
            process: Some(child),
            #[cfg(unix)]
            cdp_pipe: Some(cdp_pipe),
            #[cfg(not(unix))]
            cdp_pipe: None,
            startup_diagnostics: diagnostics,
        })
    }
}

impl LaunchedBrowser {
    pub fn shutdown(&mut self) -> Result<(), GatewayError> {
        if let Some(mut process) = self.process.take() {
            tracing::info!(instance_id = %self.instance.instance_id, "stopping managed Chrome");
            process.kill()?;
            let _ = process.wait();
        }
        self.cdp_pipe = None;
        Ok(())
    }
}

impl Drop for LaunchedBrowser {
    fn drop(&mut self) {
        let _ = self.shutdown();
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

    #[test]
    #[ignore = "requires a locally installed Chrome binary"]
    fn real_chrome_uses_the_private_devtools_pipe() {
        let chrome = BrowserLauncher::find_default_chrome_binary();
        let extension = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../extension");
        let native_host = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/secretctl-native-host");
        let profile = tempfile::tempdir().unwrap();
        let mut launched = BrowserLauncher::new(chrome, extension)
            .native_host(native_host)
            .headless(true)
            .launch(Some(profile.path().to_path_buf()), false)
            .unwrap();
        let version = launched
            .cdp_pipe
            .as_ref()
            .unwrap()
            .request(
                &crate::CdpFilter::new(),
                "Browser.getVersion",
                None,
                serde_json::json!({}),
            )
            .unwrap();
        assert!(
            version
                .get("product")
                .and_then(serde_json::Value::as_str)
                .is_some()
        );
        launched.shutdown().unwrap();
    }
}
