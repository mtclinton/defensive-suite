// defensive-suite desktop console (Tauri v2 · Phase 1 / M2).
//
// A native window that reuses the suite's dashboard, a system-tray icon, and
// native notifications when the local collector's posture reaches high/critical.
// Read-only for now — the manual-response panel and the privileged action path
// arrive in M3 (the GUI will request actions from the root agentd, never perform
// them itself). See docs/PHASE1_DESIGN.md.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use std::{thread, time::Duration};

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Manager,
};
use tauri_plugin_notification::NotificationExt;

/// Where the collector listens. Override with DSUITE_COLLECTOR.
fn collector_base() -> String {
    std::env::var("DSUITE_COLLECTOR").unwrap_or_else(|_| "http://127.0.0.1:8787".into())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // --- system tray ---
            let show = MenuItem::with_id(app, "show", "Show console", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let _tray = TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("defensive-suite")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => app.exit(0),
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    _ => {}
                })
                .build(app)?;

            // --- background posture poller → native notifications ---
            let handle = app.handle().clone();
            thread::spawn(move || poll_loop(handle));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running the defensive-suite console");
}

/// Polls the collector's summary and fires a native notification when the worst
/// severity transitions into high/critical.
fn poll_loop(app: AppHandle) {
    let url = format!("{}/api/summary", collector_base());
    let mut last = String::new();
    loop {
        if let Some(worst) = fetch_worst(&url) {
            if worst != last && (worst == "critical" || worst == "high") {
                let _ = app
                    .notification()
                    .builder()
                    .title("defensive-suite")
                    .body(format!("Posture is now {}", worst.to_uppercase()))
                    .show();
            }
            last = worst;
        }
        thread::sleep(Duration::from_secs(15));
    }
}

fn fetch_worst(url: &str) -> Option<String> {
    let body = ureq::get(url)
        .timeout(Duration::from_secs(5))
        .call()
        .ok()?
        .into_string()
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    v.get("worst")?.as_str().map(str::to_string)
}
