# Phase 1 — continuous agent + manual response + prevention (design)

**Status:** design / spec. No code committed against this yet.
**Parent:** [`ENDPOINT_PROTECTION.md`](ENDPOINT_PROTECTION.md) (the EPP/EDR roadmap).

## Decisions locked (the four open questions, resolved)

| Decision | Choice | Consequence |
|----------|--------|-------------|
| Scope | **Single host** (personal Linux workstation) | no fleet/management tier (roadmap Phase 5 dropped) |
| Response | **Manual only** for now | human-in-loop; no auto-containment (roadmap Phase 4 deferred) |
| Plumbing | **Tetragon** | eBPF detect **+ enforce**; skip Falco/Wazuh for now |
| Prevention | **On** | real blocking (SIGKILL / exec-deny), not just alerts |
| Console | **Tauri** (not Electron) | ~3 MB native-webview app reusing the existing dashboard, ~50% less RAM, far smaller attack surface |

## Why Tetragon (verified)

Tetragon runs **standalone on any Linux host** (not just Kubernetes) as a daemon, and is the
only one of the three candidates that **enforces inline**: a TracingPolicy can `Signal`
(send `SIGKILL`) or `Override` (inject a return value, e.g. block an `execve`). It exposes
events over a **gRPC stream** (`unix:///var/run/tetragon/tetragon.sock`, consumed by
`tetra getevents`) and JSON logs. Caveat: `Override`-style blocking requires a kernel built
with **`CONFIG_BPF_KPROBE_OVERRIDE`** (check with `tetra probe`); `Signal`/`SIGKILL` is
broadly available. Policies are CRD-style YAML even off-Kubernetes.

## Architecture (single host)

```
┌──────────────────────────── the workstation ────────────────────────────┐
│                                                                          │
│  Tetragon (daemon)                                                       │
│   ├─ TracingPolicies  (observe → enforce: SIGKILL / Override)            │
│   └─ gRPC events  ─────────────┐                                         │
│                                ▼                                         │
│  agentd  (NEW · privileged Go daemon, root)                             │
│   ├─ ingest Tetragon gRPC stream → evaluate → emit findings             │
│   ├─ orchestrate the 6 scheduled detectors (authwatch … bpfsentry)      │
│   ├─ response actuators: kill · isolate · quarantine · revoke · block   │
│   └─ local response socket (root, /run/agentd.sock, token + guardrails) │
│         │ POST findings                         ▲ response requests      │
│         ▼                                        │                       │
│  collector  (EXISTING · aggregation + console server, unprivileged)     │
│   ├─ /ingest  /api/findings  /api/summary                               │
│   └─ /api/respond  ── proxies → agentd socket (audited)                 │
│         ▲ read                                   ▲ respond               │
│         │                                        │                       │
│  Tauri console  (NEW · unprivileged desktop app)                        │
│   ├─ reuses dashboard HTML  ·  tray icon  ·  native notifications        │
│   └─ "Respond ▾" → Rust command → collector /api/respond → agentd        │
│                                                                          │
│  bpfsentry  (EXISTING) ── out-of-band assurance, the trust backstop      │
└──────────────────────────────────────────────────────────────────────────┘
```

**Privilege boundary (the load-bearing rule):** only **agentd** is privileged. The Tauri
console and the collector are unprivileged; they *request* actions, agentd *performs* them
behind guardrails + an append-only audit log. The webview never runs as root.

## Components

### A. Tetragon (integrate)
- Install standalone via the released `.deb`/tarball + a systemd unit (shown, not run).
- Ship our TracingPolicies under `agent/deploy/tetragon/` (we already have a bpfsentry
  load-time policy to build on).
- Enable the gRPC server (default unix socket); agentd is the only client.

### B. `agentd` — new privileged Go daemon (build)
- **Stdlib-first**, but the Tetragon gRPC client needs protobuf/grpc — so agentd is the one
  module allowed an external dep (`tetragon/api` + `google.golang.org/grpc`), isolated here.
  Alternative for a zero-dep start: consume Tetragon's **JSON log export** (tail the file)
  instead of gRPC — keeps agentd stdlib-only for M1. *(Decision: start with JSON export,
  add gRPC later.)*
- Normalizes Tetragon events → the suite's `Finding` schema (process_exec/exit, kprobe
  file/net/bpf), evaluates them against rules, POSTs matches to the collector `/ingest`.
- Orchestrates the existing six detectors (runs them on a timer / on-trigger), so scheduled
  and real-time detection land in one place.
- Exposes `/run/agentd.sock` (root, 0600) with a small response API; every action is
  guarded, reversible where possible, and audit-logged.

### C. `collector` (extend the existing service)
- Add `POST /api/respond` — authenticated; forwards a response request to the agentd socket
  and records it. Keeps the console from talking to a root socket directly.
- (Optional, P1.5) a short-TTL **events** store for a timeline view — distinct from the kept
  **findings**. P1 keeps only findings (don't store the exec firehose).

### D. Tauri console (build)
- Reuse `dashboard/index.html` as the frontend almost verbatim (it already live-fetches the
  collector API).
- Add: **system-tray** icon (Tauri v2 unified tray; Ayatana fallback on Linux) and **native
  notifications** (tauri-plugin-notification) on new ≥High findings.
- Add a **response panel**: per finding, `Respond ▾` → `kill` / `isolate` / `quarantine` /
  `revoke-key` / `block-hash`. Each invokes a Tauri **command** (Rust) → `collector
  /api/respond` → agentd. Locked down with Tauri's **capability/permission model**, a strict
  **CSP**, and no remote content.

## Prevention policies (Phase 1 set)

Roll out **observe → enforce**, per policy, with explicit allow-lists. Enforcement on a
daily driver is a foot-gun; nothing ships in `enforce` mode by default.

| Policy | Hook | Action | Guard |
|--------|------|--------|-------|
| eBPF-rootkit load | kprobe `security_bpf_prog_load` | `SIGKILL` non-allowlisted loaders | allow-list the legit BPF loaders (Cilium, your tracer) by binary/PID — this is bpfsentry's policy with enforcement flipped on |
| `ld.so.preload` / `pam.d` / `authorized_keys` write | file-write tracepoint | alert (P1); `Override` block later | never block the package manager / your editor |
| fileless / `(deleted)` exec, X11-lock masquerade | `process_exec` | `SIGKILL` | corroborate with the existing detectors before enforce |

## Manual response actuators (agentd, verified mechanisms)

| Action | Mechanism | Reversible? | Foot-guns guarded |
|--------|-----------|-------------|-------------------|
| kill process (tree) | `SIGKILL` the PID + children | no | refuse PID 1 / kthreads / agentd itself |
| network-isolate | **nftables** table that drops all egress except the management/Tailscale interface | yes — flush the table | never drop the mgmt iface (don't lock yourself out); keep SSH/Tailscale up |
| quarantine file | move to a quarantine dir + `chattr +i` / `chmod 000` | yes | refuse paths under `/proc`, `/sys`, system-critical dirs |
| revoke SSH key | remove the offending `authorized_keys` line (authwatch already fingerprints it) | yes (kept aside) | back up the file first; refuse to empty it |
| block binary/hash | **fapolicyd** deny rule by SHA-256 / path | yes — remove the rule | dry-run the rule first; don't deny a critical system binary |

Every action: a **fresh per-action token**, an **allow/deny target list**, an **append-only
audit log**, and (where listed) a stored undo. Destructive actions require explicit operator
confirmation in the console — no automation in Phase 1.

## Data model

- **Findings** (kept): detections from the detectors *and* from agentd's rule-evaluation of
  the Tetragon stream — same `Finding` schema, so the collector/dashboard need no change.
- **Events** (raw exec/file/net firehose): high-volume; **not stored in P1** — agentd
  evaluates them in-stream and emits findings only on match. (A capped events store for a
  timeline is P1.5.)

## Security / threat-model deltas for Phase 1

Carried from the roadmap, made concrete:

- **agentd is the crown jewel** — it's the only root component and can kill/isolate. Drop it
  to the minimum capabilities per action; keep the response path separate and auditable.
- **Response is a weaponizable primitive** — a hijacked isolate/kill is a DoS. Mitigations:
  manual-only, target allow/deny lists, refuse self/PID-1/mgmt-iface, reversible + undo,
  per-action token, audit log.
- **Enforcement can brick the daily driver** — start every policy in observe, allow-list
  legit behavior, flip to enforce one policy at a time.
- **The on-host agent can be lied to** by a kernel implant (the suite's founding thesis) —
  so **bpfsentry's out-of-band check stays the trust backstop**; agentd is never the sole
  source of truth.
- **Console ↔ agentd** authenticate over the local socket with a token; the unprivileged
  webview can request but never perform privileged actions.

## Milestones (each independently useful)

| # | Goal | Done when |
|---|------|-----------|
| **M1** | real-time detection | Tetragon (observe) + agentd tailing its JSON export → findings appear in the collector within seconds of an exec/bpf-load |
| **M2** | desktop console | Tauri app scaffolded, reuses the dashboard, tray + native notification on a new ≥High finding |
| **M3** | manual response | agentd response socket + guardrails + audit; collector `/api/respond`; console `Respond ▾` can kill / isolate / quarantine / revoke / block; all reversible-where-listed |
| **M4** | prevention | one Tetragon policy (eBPF-rootkit load) flipped to `SIGKILL` with a loader allow-list; verified to block in a VM, not the daily driver |

## Build vs integrate, and stack

- **Integrate:** Tetragon (daemon + policies), fapolicyd, nftables.
- **Build (Go):** `agent/` (agentd) — privileged daemon, response actuators; extend
  `collector/` (`/api/respond` + audit).
- **Build (Rust/Tauri v2):** `console/` — the desktop app, reusing the dashboard HTML.
- **Reuse:** the six detectors, the collector, the dashboard, bpfsentry.

## Host pre-reqs to verify before M4 (don't assume)

- Kernel **BTF** present; `tetra probe` reports the needed features.
- **`CONFIG_BPF_KPROBE_OVERRIDE`** if we want `Override` blocking (SIGKILL works without it).
- `nftables` and `fapolicyd` available.

## Constraint (unchanged)

Build and unit-test only. Do **not** install Tetragon, load TracingPolicies, enable
enforcement, write nftables/fapolicyd rules, or run agentd against the live machine without
showing the commands first. Enforcement gets validated in a VM, never first on the daily
driver.
