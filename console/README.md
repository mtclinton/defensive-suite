# console — desktop app (Phase 1, M2 + M3)

A native desktop console for the [defensive-suite](../README.md), built with
**Tauri v2** (not Electron): it reuses the [dashboard](../dashboard/) as its UI,
adds a **system-tray** icon and **native notifications**, and shows your *live*
collector data — at ~3 MB and a fraction of Electron's memory/attack surface.

## Desktop behavior

The console is an **always-on watcher**:

- **Single-instance** — launching it again just **focuses the running window**
  (shows + unminimizes + focuses) instead of opening a second copy.
- **Window-state** — it **remembers its size and position** across restarts.
- **Autostart / launch-to-tray** — it starts at login. On **first run** autostart
  is enabled by default (so it's always-on out of the box); after that your choice
  is respected — toggle it any time via the tray's checkable **"Start on login"**
  item (Show console / Start on login / Quit). When launched at login it starts
  **hidden in the tray** (via a `--hidden` flag); a manual launch opens the window
  normally. Use the tray **"Show console"** to bring it forward.
- **Notifications are per-finding** — instead of a coarse "posture changed" toast,
  the background poller (every 15 s) fires a **specific, deduped** notification for
  each new **correlated** (`⛓ Correlated threat`) or **critical** (`Critical
  finding`) finding from the collector's `/api/findings`, with the finding title
  plus the most useful locator (the `dst=…` from `related[]`, else the path).
  Findings present at launch are **baselined silently** (no flood on startup),
  each notifies **at most once**, and a burst of >5 new findings collapses into a
  single summary toast. The current posture is shown in the **tray tooltip**
  (e.g. `defensive-suite — 2 critical` / `defensive-suite — clean`), updated each
  poll. (Desktop notifications have no reliable cross-platform click handler, so
  the tray "Show console" item is the guaranteed way back into the window.)

**M3 adds a manual-response panel** (kill / isolate / quarantine / revoke-key /
block-hash). By design the GUI *requests* actions — the `respond` Rust command
holds the response token and POSTs to the collector's audited `/api/respond`,
which forwards to the privileged root `agentd`. The webview never holds the token
and the console never performs a privileged action itself; `agentd` guards,
audits, and stays **dry-run unless explicitly enabled** (see
[`../docs/PHASE1_DESIGN.md`](../docs/PHASE1_DESIGN.md) and
[`../agent/deploy/RESPONSE.md`](../agent/deploy/RESPONSE.md)).

```
console/
└── src-tauri/
    ├── Cargo.toml        # tauri v2 + notification/updater/single-instance/autostart/window-state plugins + ureq
    ├── tauri.conf.json   # window, tray, CSP, frontendDist → ../../dashboard
    ├── capabilities/     # v2 permission model (core + notification + updater + window-state + autostart)
    ├── icons/            # app/tray icon
    └── src/main.rs       # tray + per-finding notifications + posture tooltip + respond command + desktop polish
```

The frontend is the suite's [dashboard](../dashboard/) loaded **directly** via
`frontendDist: "../../dashboard"` — no copy to keep in sync. The response panel
only appears in the desktop app (it needs Tauri IPC); the same dashboard in a
plain browser shows no response controls. Set
`DSUITE_RESPONSE_TOKEN` (matching the collector's `COLLECTOR_RESPONSE_TOKEN`) in
the console's environment to enable it; without it the panel reports "response is
disabled".

## Build & run (Linux desktop target)

Tauri targets the OS's native webview — on Linux that's **WebKitGTK**, so the
build host needs those dev packages plus Rust and the Tauri CLI:

```sh
# system deps (Debian/Ubuntu) — REVIEW before running:
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
                 librsvg2-dev build-essential curl wget file
# Rust + Tauri CLI:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # if Rust absent
cargo install tauri-cli --version '^2'

# from console/:
cargo tauri dev          # run against the live collector
cargo tauri build        # produce a .deb / AppImage
```

The window loads the dashboard, which pulls live findings from the local
collector (`http://127.0.0.1:8787` by default; override the poller with
`DSUITE_COLLECTOR`). Start the collector first (`collector/`).

## Self-update (opt-in, signed)

The console can update itself via the **Tauri v2 updater**: on launch it does one
silent check against a static `latest.json` on the GitHub release and — only when
you ask, never automatically — downloads a **signature-verified** AppImage and
relaunches (`check_update` / `install_update` commands; a native notification when
a new version appears). It is **INERT until you complete keygen**: the committed
config ships a clearly-marked **placeholder** public key and
`createUpdaterArtifacts: false`, so the default build (and CI's no-secret dry-run)
stays green and never updates. The **private** signing key and any OS code-signing
certs are operator-owned CI secrets — never in this repo. Full enablement runbook
(keygen, the two GitHub secrets, how `latest.json` is published, plus mac/Windows
OS code-signing) is in [`UPDATING.md`](UPDATING.md), and the keypair is generated
with `make console-keygen`.

## Notes

- The app embeds `../dashboard/index.html` directly (`frontendDist`), so there is
  no generated `dist/` to keep in sync — edit the dashboard and rebuild.
- The CSP allows the webview to reach only `'self'` and the local collector
  (`127.0.0.1:8787` / `localhost:8787`) — nothing else.
- On macOS/Windows the same project builds against WKWebView / WebView2; the
  Linux build is the supported target for the suite.
