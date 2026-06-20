// defensive-suite desktop console (Tauri v2 · Phase 1 / M2).
//
// A native window that reuses the suite's dashboard, a system-tray icon, and
// native notifications when the local collector reports new correlated/critical
// findings.
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
//
// Desktop polish (always-on watcher): single-instance (a second launch focuses
// the running window), window-state (remembers size/position), and autostart
// (launches hidden to the tray at login, on by default after first run; toggle
// via the tray "Start on login" item). See console/README.md.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use std::{
    collections::{HashSet, VecDeque},
    thread,
    time::Duration,
};

use tauri::{
    menu::{CheckMenuItem, Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Manager,
};
use tauri_plugin_notification::NotificationExt;
#[cfg(desktop)]
use tauri_plugin_autostart::ManagerExt;
#[cfg(desktop)]
use tauri_plugin_updater::UpdaterExt;

/// Where the collector listens. Override with DSUITE_COLLECTOR.
fn collector_base() -> String {
    std::env::var("DSUITE_COLLECTOR").unwrap_or_else(|_| "http://127.0.0.1:8787".into())
}

/// Show + unminimize + focus the "main" webview window — the single guaranteed
/// way back into the console (used by the tray "Show console" item, the
/// single-instance callback, and a second launch).
fn focus_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
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
/// notification IN THE SAME STYLE as the finding poller when a newer signed
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
    let mut builder = tauri::Builder::default();

    // --- single-instance (MUST be the FIRST plugin registered) ---
    // A second launch of the console focuses the already-running window instead
    // of opening a new one. Registered directly on the builder, before every
    // other plugin, as the plugin requires.
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            focus_main(app);
        }));
    }

    builder
        .plugin(tauri_plugin_notification::init())
        // --- window-state: remembers the console's size + position across
        // restarts (persists on close, restores on open) automatically. ---
        .plugin(tauri_plugin_window_state::Builder::default().build())
        // --- autostart: registers the LaunchAgent integration with the
        // "--hidden" launch arg so a login-launched console starts in the tray.
        // Whether it is actually enabled is decided per-run in setup() (on by
        // default after first run; the user's later toggle is respected). ---
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--hidden"]),
        ))
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

            // --- first-run autostart default ---
            // On the FIRST run only (detected via a one-time marker file in the
            // app config dir) we enable autostart so the console is "always-on"
            // out of the box. On later runs we DO NOT touch it, so if the user
            // disables it (via the tray toggle) the choice sticks.
            #[cfg(desktop)]
            {
                if let Ok(dir) = app.path().app_config_dir() {
                    let marker = dir.join(".initialized");
                    if !marker.exists() {
                        let _ = std::fs::create_dir_all(&dir);
                        // Enable always-on by default on first run; swallow any
                        // error (e.g. no LaunchAgent dir) — autostart is a
                        // convenience, never a hard requirement.
                        let _ = app.autolaunch().enable();
                        let _ = std::fs::write(&marker, b"1");
                    }
                }
            }

            // --- system tray ---
            // "Start on login" is a CHECKABLE item reflecting the live autostart
            // state; clicking it toggles enable/disable.
            let autostart_on = {
                #[cfg(desktop)]
                {
                    app.autolaunch().is_enabled().unwrap_or(false)
                }
                #[cfg(not(desktop))]
                {
                    false
                }
            };
            let show = MenuItem::with_id(app, "show", "Show console", true, None::<&str>)?;
            let autostart_item = CheckMenuItem::with_id(
                app,
                "autostart",
                "Start on login",
                true,
                autostart_on,
                None::<&str>,
            )?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &autostart_item, &quit])?;
            let _tray = TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("defensive-suite")
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "quit" => app.exit(0),
                    "show" => focus_main(app),
                    "autostart" => {
                        #[cfg(desktop)]
                        {
                            let al = app.autolaunch();
                            // Toggle from the live state, then sync the checkmark
                            // to whatever actually took effect.
                            let now_on = al.is_enabled().unwrap_or(false);
                            let _ = if now_on {
                                al.disable()
                            } else {
                                al.enable()
                            };
                            let _ = autostart_item.set_checked(al.is_enabled().unwrap_or(false));
                        }
                    }
                    _ => {}
                })
                .build(app)?;

            // --- launch-to-tray ---
            // If launched at login (the autostart "--hidden" arg is present),
            // start in the tray by hiding the main window. A manual launch (no
            // flag) shows the window normally — which is the default, so we only
            // act on the hidden case.
            if std::env::args().any(|a| a == "--hidden") {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }

            // --- background finding poller → native notifications ---
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

/// A single finding from the collector's GET /api/findings. Every field is
/// optional/lenient so a schema drift or a partial record never crashes the
/// poller (it just yields a less specific notification).
#[derive(serde::Deserialize, Default)]
struct Finding {
    #[serde(default)]
    check: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    technique: String,
    // Parsed for completeness/forward-compat; not used in the alert text today.
    #[serde(default)]
    #[allow(dead_code)]
    confidence: String,
    #[serde(default)]
    related: Vec<String>,
}

impl Finding {
    /// Notify-worthy = a correlated realtime finding OR anything critical.
    fn is_notify_worthy(&self) -> bool {
        self.check == "realtime.correlated" || self.severity == "critical"
    }

    /// A stable key so each distinct finding notifies AT MOST once. Built from
    /// the identifying fields (not the volatile ones like confidence) so the
    /// same finding seen on a later poll dedupes to the same key.
    fn dedupe_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.check, self.severity, self.title, self.path, self.technique
        )
    }

    /// The most useful locator for the body: the "dst=..." entry from related[]
    /// if present (correlated network threats carry it), else the path, else the
    /// detail — whatever points the operator at the thing.
    fn locator(&self) -> String {
        if let Some(dst) = self.related.iter().find(|r| r.starts_with("dst=")) {
            return dst.clone();
        }
        if !self.path.is_empty() {
            return self.path.clone();
        }
        self.detail.clone()
    }
}

/// Bounded set of dedupe keys we've already notified on (or baselined). Cap is
/// ~1024; when full we evict the oldest inserted key so long-lived sessions
/// don't grow unbounded.
struct SeenSet {
    set: HashSet<String>,
    order: VecDeque<String>,
    cap: usize,
}

impl SeenSet {
    fn new(cap: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    /// True if newly inserted (not previously seen).
    fn insert(&mut self, key: String) -> bool {
        if self.set.contains(&key) {
            return false;
        }
        if self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(key.clone());
        self.order.push_back(key);
        true
    }
}

/// Lower rank = more severe; used only for the tray tooltip summary now.
fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        _ => 9,
    }
}

/// Background poller (15s). It does two things each cycle:
///   1. Fetches GET /api/findings and fires SPECIFIC, deduped native
///      notifications for new correlated/critical findings (with baseline +
///      flood control — see below).
///   2. Recomputes posture from the same findings and updates the TRAY TOOLTIP
///      (e.g. "defensive-suite — 2 critical" / "defensive-suite — clean").
///
/// Dedupe + baseline + flood control:
///   - Each notify-worthy finding has a stable key; a bounded seen-set ensures
///     each notifies at most once.
///   - On the FIRST poll we SEED the seen-set from current findings WITHOUT
///     notifying, so launching doesn't flood you with pre-existing findings.
///   - If a single poll yields >5 new notify-worthy findings we send ONE summary
///     toast instead of N (still marking them all seen).
///
/// Every failure path (offline, parse error) is swallowed: no panic, no nag.
fn poll_loop(app: AppHandle) {
    let url = format!("{}/api/findings", collector_base());
    let mut seen = SeenSet::new(1024);
    let mut baselined = false;
    loop {
        if let Some(findings) = fetch_findings(&url) {
            // Tray tooltip: posture summary from the current findings.
            let _ = update_tooltip(&app, &findings);

            // Collect the new notify-worthy findings, marking each seen.
            let mut fresh: Vec<&Finding> = Vec::new();
            for f in &findings {
                if !f.is_notify_worthy() {
                    continue;
                }
                let is_new = seen.insert(f.dedupe_key());
                // Don't notify on the very first poll — just baseline.
                if is_new && baselined {
                    fresh.push(f);
                }
            }
            baselined = true;

            if fresh.len() > 5 {
                // Flood control: one summary toast instead of N.
                let _ = app
                    .notification()
                    .builder()
                    .title("defensive-suite")
                    .body(format!(
                        "{} new critical/correlated findings",
                        fresh.len()
                    ))
                    .show();
            } else {
                for f in fresh {
                    notify_finding(&app, f);
                }
            }
        }
        thread::sleep(Duration::from_secs(15));
    }
}

/// Fire one specific notification for a single finding.
///
/// Click-to-focus: the Tauri v2 notification plugin's DESKTOP backend
/// (notify_rust) exposes no click/action callback to Rust — action handling
/// (`action_type_id` / `register_action_types`) is mobile-only (Android/iOS).
/// So there is no reliable cross-platform "click notification → focus window"
/// hook here; the tray "Show console" item is the guaranteed way back in. If a
/// portable click hook lands upstream, wire it to `focus_main(app)`.
fn notify_finding(app: &AppHandle, f: &Finding) {
    let correlated = f.check == "realtime.correlated";
    let title = if correlated {
        "⛓ Correlated threat"
    } else {
        "Critical finding"
    };
    let locator = f.locator();
    let body = if locator.is_empty() {
        f.title.clone()
    } else {
        format!("{} — {}", f.title, locator)
    };
    let _ = app
        .notification()
        .builder()
        .title(title)
        .body(body)
        .show();
}

/// Update the tray tooltip with a one-line posture summary derived from the
/// current findings ("defensive-suite — N critical" / "— N high" / "— clean").
fn update_tooltip(app: &AppHandle, findings: &[Finding]) -> tauri::Result<()> {
    let crit = findings
        .iter()
        .filter(|f| severity_rank(&f.severity) == 0)
        .count();
    let high = findings
        .iter()
        .filter(|f| severity_rank(&f.severity) == 1)
        .count();
    let tip = if crit > 0 {
        format!("defensive-suite — {crit} critical")
    } else if high > 0 {
        format!("defensive-suite — {high} high")
    } else {
        "defensive-suite — clean".to_string()
    };
    if let Some(tray) = app.tray_by_id("main") {
        tray.set_tooltip(Some(&tip))?;
    }
    Ok(())
}

/// Fetch and parse GET /api/findings. The endpoint may return either a bare
/// array or an object with a "findings" array; both are accepted. Any failure
/// (offline, non-200, bad JSON) yields None and the poller simply skips the
/// cycle — no panic, no notification.
fn fetch_findings(url: &str) -> Option<Vec<Finding>> {
    let body = ureq::get(url)
        .timeout(Duration::from_secs(5))
        .call()
        .ok()?
        .into_string()
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let arr = if v.is_array() {
        v
    } else {
        v.get("findings").cloned().unwrap_or(serde_json::Value::Null)
    };
    serde_json::from_value::<Vec<Finding>>(arr).ok()
}
