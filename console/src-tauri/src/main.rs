// defensive-suite desktop console (Tauri v2 · Phase 1 / M2).
//
// A native window that reuses the suite's dashboard, a system-tray icon, and
// native notifications when the local collector's posture reaches high/critical.
// The manual-response panel (M3) requests guarded actions from the root agentd
// via the collector's audited /api/respond — the GUI holds the response token
// and proxies, but never performs a privileged action itself (and agentd is
// dry-run unless explicitly enabled). See docs/PHASE1_DESIGN.md.

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

/// respond proxies an operator's response request to the collector's audited
/// POST /api/respond. The response bearer token lives ONLY here (env), never in
/// the webview — the UI calls this command, which adds the Authorization header.
/// The collector forwards to the root agentd, which guards/audits/executes (and
/// is dry-run unless explicitly enabled). Returns the collector's Result JSON,
/// or an error string the UI surfaces.
#[tauri::command]
fn respond(action: String, target: String, reason: String) -> Result<serde_json::Value, String> {
    let token = std::env::var("DSUITE_RESPONSE_TOKEN")
        .map_err(|_| "DSUITE_RESPONSE_TOKEN is not set — response is disabled".to_string())?;
    let body = serde_json::json!({
        "action": action, "target": target, "reason": reason, "actor": "console",
    })
    .to_string();
    match ureq::post(&format!("{}/api/respond", collector_base()))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(15))
        .send_string(&body)
    {
        Ok(r) => {
            let s = r.into_string().map_err(|e| e.to_string())?;
            serde_json::from_str::<serde_json::Value>(&s).map_err(|e| e.to_string())
        }
        Err(ureq::Error::Status(code, r)) => Err(format!(
            "collector returned {code}: {}",
            r.into_string().unwrap_or_default().trim()
        )),
        Err(e) => Err(format!("collector unreachable: {e}")),
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![respond])
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

/// Lower rank = more severe; anything below high is a no-alert sentinel.
fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        _ => 9,
    }
}

/// Polls the collector's summary and fires a native notification only when the
/// worst severity ESCALATES into high/critical (never on a de-escalation, e.g.
/// critical→high, which is an improvement and must not look like a new threat).
fn poll_loop(app: AppHandle) {
    let url = format!("{}/api/summary", collector_base());
    let mut last = String::new();
    loop {
        if let Some(worst) = fetch_worst(&url) {
            if severity_rank(&worst) <= 1 && severity_rank(&worst) < severity_rank(&last) {
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
