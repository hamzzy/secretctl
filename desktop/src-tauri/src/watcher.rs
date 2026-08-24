//! The background loop that keeps the UI honest about daemon state.
//!
//! Everything the user sees originates here: the menu-bar glyph, the push of
//! fresh data into open windows, and the notification that a decision is
//! waiting. The frontend has no other source of truth, and in particular it
//! never advances its own state after an action — it waits to be told what the
//! daemon now reports.
//!
//! When the daemon cannot be reached the loop reports [`UiProtectionState::
//! Disconnected`] rather than holding the last good state, because a stale
//! "Protected" icon during an outage is precisely the wrong answer.

use crate::admin::AdminConnection;
use crate::settings::{self, NotificationDetail};
use secretctl_protocol::{UiAuthorizationRequest, UiProtectionState, UiStatus};
use std::collections::HashSet;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

/// Idle cadence. Fast enough that the popover feels live, slow enough to stay
/// invisible in battery and CPU terms.
const IDLE_INTERVAL: Duration = Duration::from_millis(1500);

/// Cadence while something is in flight, so the progress list tracks the
/// executor closely.
const ACTIVE_INTERVAL: Duration = Duration::from_millis(400);

/// Event names the frontend listens on.
pub const EVENT_STATUS: &str = "secretctl://status";
pub const EVENT_PENDING: &str = "secretctl://pending";

pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut announced: HashSet<String> = HashSet::new();
        let mut previous_state: Option<UiProtectionState> = None;
        let mut confirmed_completion = false;

        loop {
            let connection = app.state::<AdminConnection>();
            let status: Option<UiStatus> = connection
                .call("ui.status", serde_json::json!({}))
                .await
                .ok()
                .and_then(|value| serde_json::from_value(value).ok());

            let state = status
                .as_ref()
                .map(|status| status.protection)
                .unwrap_or(UiProtectionState::Disconnected);

            if previous_state != Some(state) {
                crate::tray::apply_state(&app, state);
                announce_outcome(&app, previous_state, state, &mut confirmed_completion);
                previous_state = Some(state);
            }

            if let Some(status) = &status {
                let _ = app.emit(EVENT_STATUS, status);
            } else {
                let _ = app.emit(EVENT_STATUS, disconnected_status());
            }

            let pending: Vec<UiAuthorizationRequest> = connection
                .call("ui.pending", serde_json::json!({}))
                .await
                .ok()
                .and_then(|value| serde_json::from_value(value).ok())
                .unwrap_or_default();
            let _ = app.emit(EVENT_PENDING, &pending);

            announce_new_requests(&app, &pending, &mut announced);

            // Drop ids that are no longer pending so a later request for the
            // same agent still notifies.
            let live: HashSet<String> = pending
                .iter()
                .map(|request| request.approval_id.clone())
                .collect();
            announced.retain(|id| live.contains(id));

            let interval = match state {
                UiProtectionState::SensitiveOperation
                | UiProtectionState::ApprovalRequired
                | UiProtectionState::ProtectionInterrupted => ACTIVE_INTERVAL,
                _ => IDLE_INTERVAL,
            };
            tokio::time::sleep(interval).await;
        }
    });
}

/// Fire one notification per newly pending request.
///
/// The notification is an attention mechanism only. It carries no action that
/// authorizes anything: tapping it opens the approval window, where the actual
/// ceremony happens (spec §10).
fn announce_new_requests(
    app: &AppHandle,
    pending: &[UiAuthorizationRequest],
    announced: &mut HashSet<String>,
) {
    let settings = settings::load();
    if settings.notification_detail == NotificationDetail::Disabled {
        // Still record them, so re-enabling notifications does not replay a
        // backlog of requests that have since been decided.
        announced.extend(pending.iter().map(|request| request.approval_id.clone()));
        return;
    }

    for request in pending {
        if !announced.insert(request.approval_id.clone()) {
            continue;
        }
        let body = match settings.notification_detail {
            NotificationDetail::Detailed => format!(
                "{} wants to {} at {}.",
                request.agent_name,
                request.action_label.to_lowercase(),
                display_origin(&request.origin)
            ),
            // Minimal deliberately names neither the agent, the credential, nor
            // the site: this text can appear on a locked screen.
            _ => "An agent needs permission to perform a sensitive action.".to_string(),
        };

        let result = app
            .notification()
            .builder()
            .title("Authorization request waiting")
            .body(body)
            .show();
        if let Err(error) = result {
            tracing::warn!(%error, "could not post notification");
        }
    }

    // Bring the decision surface forward when something is waiting. The window
    // is created hidden-then-shown by `open_approval`, so this is idempotent.
    if let Some(request) = pending.first() {
        if app.get_webview_window(crate::windows::APPROVAL).is_none() {
            if let Err(error) = crate::windows::open_approval(app, &request.approval_id) {
                tracing::error!(%error, "could not open approval window");
            }
        }
    }
}

/// Confirm a finished operation, once.
///
/// The confirmation exists so the user knows the flow ended and the agent can
/// carry on — it is not a security notice, and it is suppressed entirely when
/// the user has turned notifications off. The fail-closed states are announced
/// regardless of the completion preference, because "your protection could not
/// be verified" is not a courtesy message.
fn announce_outcome(
    app: &AppHandle,
    previous: Option<UiProtectionState>,
    current: UiProtectionState,
    confirmed_completion: &mut bool,
) {
    let settings = settings::load();
    if settings.notification_detail == NotificationDetail::Disabled {
        return;
    }
    // Only report an outcome that follows an operation we actually saw start.
    let was_active = matches!(
        previous,
        Some(UiProtectionState::SensitiveOperation) | Some(UiProtectionState::ApprovalRequired)
    );

    let (title, body) = match current {
        UiProtectionState::Completed if was_active && settings.confirm_completion => {
            if *confirmed_completion {
                return;
            }
            *confirmed_completion = true;
            (
                "Authentication completed",
                "The agent can continue its task.".to_string(),
            )
        }
        UiProtectionState::ProtectionInterrupted => (
            "Protection interrupted",
            "secretctl could no longer verify browser protection, so credential \
             release was halted."
                .to_string(),
        ),
        UiProtectionState::OutcomeUncertain => (
            "Result could not be verified",
            "The operation may have completed, but secretctl lost confirmation \
             from the browser. No further credential operation will run until \
             the session is re-established."
                .to_string(),
        ),
        _ => {
            if current == UiProtectionState::SensitiveOperation {
                *confirmed_completion = false;
            }
            return;
        }
    };

    if let Err(error) = app.notification().builder().title(title).body(body).show() {
        tracing::warn!(%error, "could not post outcome notification");
    }
}

fn display_origin(origin: &str) -> String {
    origin
        .split("://")
        .nth(1)
        .unwrap_or(origin)
        .trim_end_matches(":443")
        .to_string()
}

/// The status the UI shows when the daemon is unreachable: fail closed, and say
/// so plainly.
fn disconnected_status() -> UiStatus {
    UiStatus {
        protection: UiProtectionState::Disconnected,
        pending_approvals: 0,
        active_operation: None,
        browser_sessions_connected: 0,
        agents_enrolled: 0,
        agents_active: 0,
        active_grants: 0,
        providers: Vec::new(),
        policy_fingerprint: String::new(),
        audit_chain_intact: false,
    }
}
