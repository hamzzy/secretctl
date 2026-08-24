//! The complete set of operations the frontend can invoke.
//!
//! Every command here is a thin pass-through to `secretctld`. None of them
//! decides anything: "approve" sends an approval id and the digest the user was
//! shown, and the daemon then re-verifies independently that the approval
//! exists, has not expired, belongs to this principal, still matches a live
//! measured page, and satisfies policy. A frontend that lied about any of it
//! would simply be refused (spec §30).
//!
//! Nothing in this file reads a credential, opens a provider, or touches the
//! executor. There is deliberately no command that returns secret material,
//! because there is no such value anywhere in this process.

use crate::admin::{AdminConnection, BrokerError};
use crate::presence;
use base64::Engine;
use secretctl_protocol::{
    UiActivityEvent, UiAgent, UiAuthorizationRequest, UiBrowserSession, UiCredential, UiGrant,
    UiStatus,
};
use serde::Serialize;
use tauri::{Manager, State};

/// Error shape handed to the frontend.
///
/// `code` is present only when the broker itself refused, and the UI keeps it
/// behind a technical-details disclosure: a user seeing "authentication
/// blocked" should not be shown `EPOCH_INVALIDATED (-32006)` as the headline
/// (spec §19).
#[derive(Debug, Serialize)]
pub struct CommandError {
    pub message: String,
    pub code: Option<i32>,
    /// True when the daemon could not be reached at all, which the UI renders
    /// as the fail-closed Disconnected state rather than as a failed action.
    pub disconnected: bool,
}

impl From<anyhow::Error> for CommandError {
    fn from(error: anyhow::Error) -> Self {
        if let Some(broker) = error.downcast_ref::<BrokerError>() {
            return Self {
                message: broker.message.clone(),
                code: Some(broker.code),
                disconnected: false,
            };
        }
        Self {
            message: error.to_string(),
            code: None,
            disconnected: true,
        }
    }
}

type CommandResult<T> = Result<T, CommandError>;

async fn query<T: serde::de::DeserializeOwned>(
    connection: &AdminConnection,
    method: &str,
    params: serde_json::Value,
) -> CommandResult<T> {
    let value = connection.call(method, params).await?;
    serde_json::from_value(value).map_err(|error| CommandError {
        message: format!("daemon sent an unreadable {method} response: {error}"),
        code: None,
        disconnected: false,
    })
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_status(connection: State<'_, AdminConnection>) -> CommandResult<UiStatus> {
    query(&connection, "ui.status", serde_json::json!({})).await
}

#[tauri::command]
pub async fn get_pending_requests(
    connection: State<'_, AdminConnection>,
) -> CommandResult<Vec<UiAuthorizationRequest>> {
    query(&connection, "ui.pending", serde_json::json!({})).await
}

/// Re-read one pending request. The approval window calls this on open so it
/// renders the request as the daemon currently sees it, not as it was when the
/// notification fired.
#[tauri::command]
pub async fn get_pending_request(
    connection: State<'_, AdminConnection>,
    approval_id: String,
) -> CommandResult<UiAuthorizationRequest> {
    query(
        &connection,
        "ui.pending_one",
        serde_json::json!({ "approval_id": approval_id }),
    )
    .await
}

#[tauri::command]
pub async fn get_activity(
    connection: State<'_, AdminConnection>,
    limit: Option<u32>,
) -> CommandResult<Vec<UiActivityEvent>> {
    query(
        &connection,
        "ui.activity",
        serde_json::json!({ "limit": limit.unwrap_or(50) }),
    )
    .await
}

#[tauri::command]
pub async fn get_agents(connection: State<'_, AdminConnection>) -> CommandResult<Vec<UiAgent>> {
    query(&connection, "ui.agents", serde_json::json!({})).await
}

#[tauri::command]
pub async fn get_credentials(
    connection: State<'_, AdminConnection>,
) -> CommandResult<Vec<UiCredential>> {
    query(&connection, "ui.credentials", serde_json::json!({})).await
}

#[tauri::command]
pub async fn get_browser_sessions(
    connection: State<'_, AdminConnection>,
) -> CommandResult<Vec<UiBrowserSession>> {
    query(&connection, "ui.browser_sessions", serde_json::json!({})).await
}

#[tauri::command]
pub async fn get_grants(
    connection: State<'_, AdminConnection>,
    include_revoked: Option<bool>,
) -> CommandResult<Vec<UiGrant>> {
    query(
        &connection,
        "grant.list",
        serde_json::json!({ "include_revoked": include_revoked.unwrap_or(false) }),
    )
    .await
}

// ---------------------------------------------------------------------------
// Decide
// ---------------------------------------------------------------------------

/// Decode the digest the UI echoes back.
///
/// The frontend receives this value inside the request it renders and returns
/// it unchanged. It binds the click to the request that was actually displayed;
/// the daemon separately confirms the page has not navigated since.
fn decode_digest(context_digest: &str) -> CommandResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(context_digest)
        .map_err(|_| CommandError {
            message: "The approval could not be matched to the request you were shown.".to_string(),
            code: None,
            disconnected: false,
        })
}

#[tauri::command]
pub async fn approve_once(
    connection: State<'_, AdminConnection>,
    approval_id: String,
    context_digest: String,
    requires_presence: bool,
) -> CommandResult<serde_json::Value> {
    let presence_verified = if requires_presence {
        presence::verify("authorize this credential operation").await?
    } else {
        false
    };
    connection
        .call(
            "approval.decide",
            serde_json::json!({
                "approval_id": approval_id,
                "decision": "approve",
                "context_digest": decode_digest(&context_digest)?,
                "presence_verified": presence_verified,
            }),
        )
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn deny(
    connection: State<'_, AdminConnection>,
    approval_id: String,
    context_digest: String,
) -> CommandResult<serde_json::Value> {
    // Denial never requires presence: refusing authority is always permitted.
    connection
        .call(
            "approval.decide",
            serde_json::json!({
                "approval_id": approval_id,
                "decision": "deny",
                "context_digest": decode_digest(&context_digest)?,
                "presence_verified": false,
            }),
        )
        .await
        .map_err(CommandError::from)
}

/// Approve, and create the standing authorization covering the same tuple.
///
/// Widening authority beyond a single use always requires verified user
/// presence, regardless of what the underlying policy decision demanded
/// (spec §15).
#[tauri::command]
pub async fn create_grant(
    connection: State<'_, AdminConnection>,
    approval_id: String,
    context_digest: String,
    ttl_days: i64,
) -> CommandResult<serde_json::Value> {
    let presence_verified = presence::verify("create a standing authorization").await?;
    connection
        .call(
            "grant.create",
            serde_json::json!({
                "approval_id": approval_id,
                "context_digest": decode_digest(&context_digest)?,
                "ttl_days": ttl_days,
                "presence_verified": presence_verified,
            }),
        )
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn revoke_grant(
    connection: State<'_, AdminConnection>,
    selector: String,
) -> CommandResult<serde_json::Value> {
    connection
        .call(
            "grant.revoke",
            serde_json::json!({ "selector": selector, "reason": "revoked by user" }),
        )
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub async fn disable_agent(
    connection: State<'_, AdminConnection>,
    agent_id: String,
) -> CommandResult<serde_json::Value> {
    connection
        .call("agent.disable", serde_json::json!({ "agent_id": agent_id }))
        .await
        .map_err(CommandError::from)
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// Open the approval window for one request.
///
/// The notification is only an attention mechanism; the decision is always made
/// here, in a window the application owns and the agent cannot reach (spec §10).
#[tauri::command]
pub async fn open_approval(app: tauri::AppHandle, approval_id: String) -> CommandResult<()> {
    crate::windows::open_approval(&app, &approval_id).map_err(CommandError::from)
}

#[tauri::command]
pub async fn open_manage(app: tauri::AppHandle, section: String) -> CommandResult<()> {
    crate::windows::open_manage(&app, &section).map_err(CommandError::from)
}

#[tauri::command]
pub async fn close_window(window: tauri::Window) -> CommandResult<()> {
    let _ = window.hide();
    Ok(())
}

/// Diagnostics for the Disconnected state.
///
/// Reports what the app can observe about the installation without acting on
/// it. Restarting the service is deliberately *not* a command: the frontend has
/// no process or shell permission, and the UI tells the user which CLI command
/// to run instead of quietly acquiring that authority.
#[derive(Debug, Serialize)]
pub struct Diagnostics {
    pub installation_dir: String,
    pub broker_key_pinned: bool,
    pub admin_socket_present: bool,
    pub agent_socket_present: bool,
    pub executor_socket_present: bool,
    pub daemon_reachable: bool,
    pub restart_command: &'static str,
}

#[tauri::command]
pub async fn get_diagnostics(connection: State<'_, AdminConnection>) -> CommandResult<Diagnostics> {
    let directory = crate::admin::installation_dir();
    let run = directory.join("run");
    Ok(Diagnostics {
        broker_key_pinned: directory.join("broker_key.pub").exists(),
        admin_socket_present: run.join("admin.sock").exists(),
        agent_socket_present: run.join("agent.sock").exists(),
        executor_socket_present: run.join("executor.sock").exists(),
        daemon_reachable: connection.is_reachable().await,
        installation_dir: directory.display().to_string(),
        restart_command: "secretctl start",
    })
}

/// Whether onboarding has been completed, tracked as a marker file in the
/// installation directory so it survives reinstalls of the app bundle.
#[tauri::command]
pub async fn get_onboarding_complete() -> CommandResult<bool> {
    Ok(crate::admin::installation_dir()
        .join("desktop-onboarded")
        .exists())
}

#[tauri::command]
pub async fn set_onboarding_complete(app: tauri::AppHandle) -> CommandResult<()> {
    let marker = crate::admin::installation_dir().join("desktop-onboarded");
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&marker, b"1").map_err(|error| CommandError {
        message: error.to_string(),
        code: None,
        disconnected: false,
    })?;
    if let Some(window) = app.get_webview_window("onboarding") {
        let _ = window.close();
    }
    Ok(())
}
