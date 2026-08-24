//! Window construction.
//!
//! The application owns four surfaces and creates no others:
//!
//! * `popover`   — the compact panel under the menu-bar icon
//! * `approval`  — the authorization ceremony, one request at a time
//! * `manage`    — activity, agents, grants, credentials, browsers, settings
//! * `onboarding` — first run only
//!
//! Every one is loaded from the bundled frontend at a fixed route. Nothing here
//! ever navigates to a URL derived from data, so no agent-controlled string can
//! steer a window anywhere.

use tauri::{
    AppHandle, LogicalPosition, LogicalSize, Manager, WebviewUrl, WebviewWindow,
    WebviewWindowBuilder,
};

pub const POPOVER: &str = "popover";
pub const APPROVAL: &str = "approval";
pub const MANAGE: &str = "manage";
pub const ONBOARDING: &str = "onboarding";

const POPOVER_SIZE: (f64, f64) = (360.0, 520.0);
const APPROVAL_SIZE: (f64, f64) = (420.0, 640.0);
const MANAGE_SIZE: (f64, f64) = (900.0, 620.0);
const ONBOARDING_SIZE: (f64, f64) = (520.0, 560.0);

fn route(path: &str) -> WebviewUrl {
    WebviewUrl::App(format!("index.html#{path}").into())
}

/// Build the popover: frameless, non-resizable, and dismissed on blur, which is
/// what makes it read as a menu-bar panel rather than a window.
pub fn build_popover(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let window = WebviewWindowBuilder::new(app, POPOVER, route("/popover"))
        .title("secretctl")
        .inner_size(POPOVER_SIZE.0, POPOVER_SIZE.1)
        .resizable(false)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .visible(false)
        .focused(false)
        .build()?;

    // Dismissing on blur is the expected menu-bar behaviour, and it also means
    // the popover cannot linger showing a stale security state behind other
    // windows.
    let handle = window.clone();
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::Focused(false) = event {
            let _ = handle.hide();
        }
    });
    Ok(window)
}

/// Show the popover anchored under the menu-bar icon.
pub fn toggle_popover(app: &AppHandle, tray_rect: Option<(f64, f64, f64)>) -> tauri::Result<()> {
    let window = match app.get_webview_window(POPOVER) {
        Some(window) => window,
        None => build_popover(app)?,
    };
    if window.is_visible().unwrap_or(false) {
        window.hide()?;
        return Ok(());
    }

    if let Some((icon_x, icon_y, icon_width)) = tray_rect {
        let scale = window.scale_factor().unwrap_or(1.0);
        let x = icon_x / scale + icon_width / scale / 2.0 - POPOVER_SIZE.0 / 2.0;
        let y = icon_y / scale + 6.0;
        window.set_position(LogicalPosition::new(x.max(8.0), y))?;
    }
    window.show()?;
    window.set_focus()?;
    Ok(())
}

/// Open the approval ceremony for one request.
///
/// The approval id is placed in the route, and the window immediately re-reads
/// the request from the daemon rather than trusting anything carried in.
pub fn open_approval(app: &AppHandle, approval_id: &str) -> anyhow::Result<()> {
    // Approval ids are broker-minted; refuse anything that is not one rather
    // than interpolating an arbitrary string into a URL.
    anyhow::ensure!(
        approval_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "malformed approval id"
    );

    if let Some(window) = app.get_webview_window(APPROVAL) {
        let _ = window.close();
    }
    let window = WebviewWindowBuilder::new(
        app,
        APPROVAL,
        route(&format!("/approval/{approval_id}")),
    )
    .title("Authorization requested")
    .inner_size(APPROVAL_SIZE.0, APPROVAL_SIZE.1)
    .resizable(false)
    .always_on_top(true)
    .center()
    .focused(true)
    .build()?;
    window.set_focus()?;
    if let Some(popover) = app.get_webview_window(POPOVER) {
        let _ = popover.hide();
    }
    Ok(())
}

pub fn open_manage(app: &AppHandle, section: &str) -> anyhow::Result<()> {
    const SECTIONS: &[&str] = &[
        "activity",
        "agents",
        "grants",
        "credentials",
        "browsers",
        "settings",
        "diagnostics",
    ];
    anyhow::ensure!(SECTIONS.contains(&section), "unknown section");

    if let Some(window) = app.get_webview_window(MANAGE) {
        window.eval(format!("window.location.hash = '/manage/{section}'"))?;
        window.show()?;
        window.set_focus()?;
        return Ok(());
    }
    let window = WebviewWindowBuilder::new(app, MANAGE, route(&format!("/manage/{section}")))
        .title("secretctl")
        .inner_size(MANAGE_SIZE.0, MANAGE_SIZE.1)
        .min_inner_size(720.0, 480.0)
        .center()
        .build()?;
    window.set_focus()?;
    if let Some(popover) = app.get_webview_window(POPOVER) {
        let _ = popover.hide();
    }
    Ok(())
}

pub fn open_onboarding(app: &AppHandle) -> anyhow::Result<()> {
    if let Some(window) = app.get_webview_window(ONBOARDING) {
        window.show()?;
        window.set_focus()?;
        return Ok(());
    }
    let window = WebviewWindowBuilder::new(app, ONBOARDING, route("/onboarding"))
        .title("Welcome to secretctl")
        .inner_size(ONBOARDING_SIZE.0, ONBOARDING_SIZE.1)
        .resizable(false)
        .center()
        .build()?;
    window.set_size(LogicalSize::new(ONBOARDING_SIZE.0, ONBOARDING_SIZE.1))?;
    window.set_focus()?;
    Ok(())
}
