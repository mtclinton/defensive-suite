# defensive-suite

A personal defensive security suite for a Linux developer workstation, targeting the
specific threat cluster that endangers a machine like this one: a poisoned dependency
that executes at install time, harvests the credential files that gate build pipelines,
and then hides kernel-resident via an eBPF rootkit.

Six composable tools, mostly Go with eBPF where it earns its place, plus a Python
forensics path for the one problem that can't be solved from the live kernel.

## Collector & dashboard

The [`collector/`](collector/) service is the aggregation keystone: every tool POSTs its
`Report` JSON to one bearer-authed `/ingest` endpoint, and it serves the dashboard with
live, local data — the "one local collector" the architecture is built around. A single
static Go binary; bind it to a private/Tailscale interface.

A static, dependency-free build of that same dashboard lives in [`dashboard/`](dashboard/)
and is published via GitHub Pages:
**<https://mtclinton.github.io/defensive-suite/dashboard/>** — findings filterable by
tool / severity / ATT&CK technique, the threat-model → defense map, and per-tool posture.
The public page shows **sample** data; served by the collector it shows your **real**
findings (which never leave your network). No build step.

## The tools

| Tool | Job | Primary stack |
|------|-----|---------------|
| `authwatch` | Auth-stack & persistence integrity (PAM / OpenSSH / `authorized_keys` / `ld.so.preload`) | Go + AIDE + auditd |
| `instguard` | Supply-chain install-time guard (npm / pip / AUR hooks, lockfile drift, OSV) | Go |
| `credsentinel` | Secret-exposure scanner + honeytokens | Go + gitleaks/TruffleHog + Canarytokens |
| `egresswatch` | Egress visibility + magic-packet backdoor detection | Go + eBPF (cilium/ebpf) |
| `posturescan` | Kernel & container hardening posture (sysctls, caps, rootless Podman) | Go/Python + Lynis/OpenSCAP |
| `bpfsentry` | **Flagship.** Offline eBPF-program enumerator + out-of-band memory forensics | Go (cilium/ebpf) + Python (Volatility 3) |

Each tool directory is self-contained and carries its own `DESIGN.md`. The full
threat-to-defense mapping lives in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md); the
design/decision doc for evolving the suite into endpoint protection (EPP/EDR) is in
[`docs/ENDPOINT_PROTECTION.md`](docs/ENDPOINT_PROTECTION.md), with the scoped Phase 1 build
spec (Tetragon + agent + Tauri console + manual response) in
[`docs/PHASE1_DESIGN.md`](docs/PHASE1_DESIGN.md).

## Build order

Front-loaded by attack probability and quick wins:

1. **`authwatch` + `credsentinel`** — counter the most common chain (poisoned dep → credential theft → PAM/persistence) and tell you immediately whether you're already compromised.
2. **`instguard`** — stop the *next* poisoned install before it executes.
3. **`posturescan`** — set `ptrace_scope=2`, `unprivileged_bpf_disabled=2`, `lockdown=confidentiality`.
4. **`egresswatch`** — application firewall + the magic-packet detection rule.
5. **`bpfsentry`** — the deep build: load-time alerting, early-boot baseline, offline memory forensics.

## Architecture principle

At least one detection path must **not** run on the potentially-compromised kernel.
A live host with an eBPF rootkit lies to `ps`, `ss`, `bpftool`, and every eBPF-based
EDR. `bpfsentry` therefore includes early-boot baselining and offline memory acquisition
(KVM hypervisor snapshot is the trusted path on this homelab).

Route every tool's output — authwatch diffs, instguard verdicts, credsentinel/Canarytoken
trips, egresswatch denials, posturescan drift, bpfsentry divergences — to one local
collector over Tailscale. Store the trust anchors (AIDE DBs, BPF allowlists, memory
dumps) on an isolated host the monitored machines can write to but not read or rewrite.

## Building each tool with Claude Code

Per-tool, point Claude Code at the directory and its design doc:

```sh
cd authwatch
claude
# > Build this tool per ./DESIGN.md. Go module, single static binary, systemd timer unit.
```

The six-tool layout maps cleanly onto a parallel-subagent workflow — one subagent per
directory, since the tools share nothing but the collector contract.

## Layout

```
defensive-suite/
├── docs/THREAT_MODEL.md     # cybercrime.club posts → defenses
├── authwatch/DESIGN.md
├── instguard/DESIGN.md
├── credsentinel/DESIGN.md
├── egresswatch/DESIGN.md
├── posturescan/DESIGN.md
└── bpfsentry/DESIGN.md
```

To split this into separate repos instead of a monorepo, each tool directory is already
self-contained — `git init` inside any of them and it stands alone. `bpfsentry` is the
one most worth breaking out on its own.

## Licensing

Add a `LICENSE` before publishing — your choice (Apache-2.0 or MIT keep it permissive).
One caveat that matters: these tools **call** mature OSS (AIDE, OpenSnitch, Tetragon,
Lynis, Volatility 3) as separate binaries, which carries no license obligation. If you
instead **vendor or fork** their code into this repo — especially Volatility 3 and its
eBPF plugins (GPL) — their licenses, several copyleft, attach and must be honored.