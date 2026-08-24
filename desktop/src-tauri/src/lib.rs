//! secretctl desktop — the human control surface for `secretctld`.
//!
//! This process is a *client* of the security daemon, never the authority. It
//! holds no credential, no capability, and no policy; it renders what the
//! daemon reports and relays what the human decides. The daemon re-verifies
//! every decision on its own terms (spec §30, §43).

mod admin;
mod commands;
mod presence;
mod settings;
mod tray;
mod watcher;
mod windows;

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secretctl_desktop=info".into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(admin::AdminConnection::new())
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_pending_requests,
            commands::get_pending_request,
            commands::get_activity,
            commands::get_agents,
            commands::get_credentials,
            commands::get_browser_sessions,
            commands::get_grants,
            commands::approve_once,
            commands::deny,
            commands::create_grant,
            commands::revoke_grant,
            commands::disable_agent,
            commands::open_approval,
            commands::open_manage,
            commands::close_window,
            commands::get_diagnostics,
            commands::get_onboarding_complete,
            commands::set_onboarding_complete,
            settings::get_settings,
            settings::set_settings,
        ])
        .setup(|app| {
            let handle = app.handle().clone();

            // Menu-bar only: no Dock tile, no window on launch. On a healthy
            // machine the user should see nothing but the icon (spec §5, §28).
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            tray::build(&handle)?;
            windows::build_popover(&handle)?;
            watcher::spawn(handle.clone());

            if !admin::installation_dir().join("desktop-onboarded").exists() {
                // First run is the one time a window opens by itself.
                #[cfg(target_os = "macos")]
                let _ = handle.set_activation_policy(tauri::ActivationPolicy::Regular);
                windows::open_onboarding(&handle)?;
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing a management window returns to menu-bar-only rather than
            // terminating: the daemon keeps running and the icon must stay.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() != windows::ONBOARDING {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to start secretctl desktop")
        .run(|_app, event| {
            // Never exit just because the last window closed.
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                if code.is_none() {
                    api.prevent_exit();
                }
            }
        });
}
