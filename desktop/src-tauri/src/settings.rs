//! Local UI preferences.
//!
//! These are presentation choices only — nothing here relaxes a security
//! control, and the daemon never reads this file. It lives beside the
//! installation rather than in the app bundle so it survives reinstalling the
//! application.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How much a macOS notification is allowed to reveal.
///
/// Notifications can appear on a locked screen and in Notification Centre, so
/// the default discloses nothing beyond the fact that a decision is waiting
/// (spec §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDetail {
    #[default]
    Minimal,
    Detailed,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub notification_detail: NotificationDetail,
    /// Show the brief success confirmation after an operation completes.
    pub confirm_completion: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            notification_detail: NotificationDetail::Minimal,
            confirm_completion: true,
        }
    }
}

fn settings_path() -> PathBuf {
    crate::admin::installation_dir().join("desktop-settings.json")
}

pub fn load() -> Settings {
    std::fs::read(settings_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save(settings: &Settings) -> anyhow::Result<()> {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(settings)?)?;
    Ok(())
}

#[tauri::command]
pub async fn get_settings() -> Result<Settings, crate::commands::CommandError> {
    Ok(load())
}

#[tauri::command]
pub async fn set_settings(settings: Settings) -> Result<(), crate::commands::CommandError> {
    save(&settings).map_err(|error| crate::commands::CommandError {
        message: error.to_string(),
        code: None,
        disconnected: false,
    })
}
