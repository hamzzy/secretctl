use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const HOST_NAME: &str = "com.secretctl.native_host";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeHostManifest {
    pub name: String,
    pub description: String,
    pub path: String,
    pub r#type: String,
    pub allowed_origins: Vec<String>,
}

impl NativeHostManifest {
    pub fn new(binary_path: impl AsRef<Path>, allowed_extension_id: &str) -> Self {
        Self {
            name: HOST_NAME.to_string(),
            description: "secretctl Chrome Native Messaging Host".to_string(),
            path: binary_path.as_ref().to_string_lossy().to_string(),
            r#type: "stdio".to_string(),
            allowed_origins: vec![format!("chrome-extension://{}/", allowed_extension_id)],
        }
    }

    pub fn default_manifest_path() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home)
                .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
                .join(format!("{}.json", HOST_NAME))
        }

        #[cfg(target_os = "linux")]
        {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home)
                .join(".config/google-chrome/NativeMessagingHosts")
                .join(format!("{}.json", HOST_NAME))
        }

        #[cfg(target_os = "windows")]
        {
            let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(local_app_data)
                .join("secretctl")
                .join(format!("{}.json", HOST_NAME))
        }
    }

    pub async fn install(&self, target_path: Option<PathBuf>) -> anyhow::Result<PathBuf> {
        let path = target_path.unwrap_or_else(Self::default_manifest_path);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let json_content = serde_json::to_string_pretty(self)?;
        tokio::fs::write(&path, json_content).await?;
        Ok(path)
    }
}
