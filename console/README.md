# console — desktop app (Phase 1, M2 + M3)

A native desktop console for the [defensive-suite](../README.md), built with
**Tauri v2** (not Electron): it reuses the [dashboard](../dashboard/) as its UI,
adds a **system-tray** icon and **native notifications**, and shows your *live*
collector data — at ~3 MB and a fraction of Electron's memory/attack surface.

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
├── dist/                 # the frontend = the dashboard (mirror of ../dashboard/index.html)
└── src-tauri/
    ├── Cargo.toml        # tauri v2 + notification plugin + ureq (collector poll/respond)
    ├── tauri.conf.json   # window, tray, CSP, frontendDist
    ├── capabilities/     # v2 permission model (core + notification)
    ├── icons/            # app/tray icon
    └── src/main.rs       # tray + native notifications + posture poller + respond command
```

The response panel only appears in the desktop app (it needs Tauri IPC); the same
`dist/index.html` in a plain browser shows no response controls. Set
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

## Notes

- `dist/index.html` mirrors `../dashboard/index.html`; regenerate it with
  `cp ../dashboard/index.html dist/index.html` when the dashboard changes.
- The CSP allows the webview to reach only `'self'` and the local collector
  (`127.0.0.1:8787` / `localhost:8787`) — nothing else.
- On macOS/Windows the same project builds against WKWebView / WebView2; the
  Linux build is the supported target for the suite.
