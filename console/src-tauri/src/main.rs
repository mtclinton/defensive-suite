// defensive-suite desktop console (Tauri v2 · Phase 1 / M2).
//
// A native window that reuses the suite's dashboard, a system-tray icon, and
// native notifications when the local collector's posture reaches high/critical.
// The manual-response panel (M3) requests guarded actions from the root agentd
// via the collector's audited /api/respond — the GUI holds the response token
// and proxies, but never performs a privileged action itself (and agentd is
// dry-run unless explicitly enabled). See docs/PHASE1_DESIGN.md.
//
// Self-update (M4): a desktop-gated Tauri updater plugin. The console checks a
// static latest.json on the GitHub release for a newer, SIGNATURE-VERIFIED
// AppImage and — only when the operator asks — downloads + installs + relaunches.
// It is INERT until the operator runs `make console-keygen`, pastes the PUBLIC
// key into tauri.conf plugins.updater.pubkey, and enables createUpdaterArtifacts
// in the release job (the PRIVATE key is a CI secret, never in this repo). See
// console/UPDATING.md.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use std::{thread, time::Duration};

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Manager,
};
use tauri_plugin_notification::NotificationExt;
#[cfg(desktop)]
use tauri_plugin_updater::UpdaterExt;

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

/// What the UI gets back from a check: whether a newer signed build exists and,
/// if so, its version (and the version we are running now).
#[derive(serde::Serialize)]
struct UpdateStatus {
    available: bool,
    current_version: String,
    version: Option<String>,
}

/// check_update asks the configured updater endpoint (the GitHub latest.json)
/// whether a newer, signature-verified build exists — WITHOUT installing it.
/// Returns gracefully on every failure path: an unset/placeholder pubkey, no
/// endpoint, or being offline all surface as "no update available" plus an error
/// string the UI can show, never a panic. The updater is INERT until the
/// operator completes keygen (see console/UPDATING.md).
#[cfg(desktop)]
#[tauri::command]
async fn check_update(app: AppHandle) -> Result<UpdateStatus, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    match updater.check().await {
        Ok(Some(update)) => Ok(UpdateStatus {
            available: true,
            current_version: update.current_version.clone(),
            version: Some(update.version.clone()),
        }),
        Ok(None) => Ok(UpdateStatus {
            available: false,
            current_version: app.package_info().version.to_string(),
            version: None,
        }),
        Err(e) => Err(format!("update check failed: {e}")),
    }
}

/// install_update downloads + installs the newer signed build, then relaunches.
/// Only ever called explicitly by the UI — the console NEVER auto-installs. The
/// download is signature-verified against the committed updater pubkey before it
/// is applied; a bad/absent signature fails here rather than installing anything.
#[cfg(desktop)]
#[tauri::command]
async fn install_update(app: AppHandle) -> Result<(), String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let update = updater
        .check()
        .await
        .map_err(|e| format!("update check failed: {e}"))?
        .ok_or_else(|| "no update available".to_string())?;
    update
        .download_and_install(|_chunk, _total| {}, || {})
        .await
        .map_err(|e| format!("update install failed: {e}"))?;
    app.restart();
}

/// One-shot, on-launch background update check. Fires a single native
/// notification IN THE SAME STYLE as the posture poller when a newer signed
/// build is available, then stops — it NEVER auto-installs and NEVER loops/nags.
/// Every failure (placeholder pubkey, no endpoint, offline) is swallowed so the
/// console behaves identically to before when the updater is inert.
#[cfg(desktop)]
fn spawn_update_check(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let Ok(updater) = app.updater() else { return };
        if let Ok(Some(update)) = updater.check().await {
            let _ = app
                .notification()
                .builder()
                .title("defensive-suite")
                .body(format!("Console update {} available", update.version))
                .show();
        }
    });
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        // The updater commands are desktop-only; this console only ever builds
        // for desktop targets, so the handler always lists them.
        .invoke_handler(tauri::generate_handler![
            respond,
            check_update,
            install_update
        ])
        .setup(|app| {
            // --- self-update plugin (desktop only) ---
            // INERT until the operator completes keygen + flips
            // createUpdaterArtifacts; registering it here is harmless with the
            // placeholder pubkey (no check runs until a command/the launch check
            // asks, and every failure path is swallowed). See console/UPDATING.md.
            #[cfg(desktop)]
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;

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

            // --- one-shot on-launch update check → native notification ---
            #[cfg(desktop)]
            spawn_update_check(app.handle().clone());

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
