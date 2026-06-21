# defensive-suite

[![CI](https://github.com/mtclinton/defensive-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/mtclinton/defensive-suite/actions/workflows/ci.yml)

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

The [`agent/`](agent/) (`agentd`) is the Phase 1 **real-time** tier (see
[`docs/PHASE1_DESIGN.md`](docs/PHASE1_DESIGN.md)): it tails [Tetragon](https://tetragon.io)'s
event stream and forwards findings to the collector within seconds — turning the scheduled
scans into continuous detection. Observe-only for now; enforcement/response are later
milestones.

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
[`docs/PHASE1_DESIGN.md`](docs/PHASE1_DESIGN.md). The (not-yet-built) **Phase 4
auto-response** policy — the design for acting on the correlation signal *without* a
human, adversarially red-teamed before any code — is in
[`docs/PHASE4_DESIGN.md`](docs/PHASE4_DESIGN.md).

## Build order

Front-loaded by attack probability and quick wins:

1. **`authwatch` + `credsentinel`** — counter the most common chain (poisoned dep → credential theft → PAM/persistence) and tell you immediately whether you're already compromised.
2. **`instguard`** — stop the *next* poisoned install before it executes.
3. **`posturescan`** — set `ptrace_scope=2`, `unprivileged_bpf_disabled=2`, `lockdown=confidentiality`.
4. **`egresswatch`** — application firewall + the magic-packet detection rule.
5. **`bpfsentry`** — the deep build: load-time alerting, early-boot baseline, offline memory forensics.

## Install

The shipped [`install.sh`](install.sh) sets up the **detection / observe tier** safely: it
installs the suite binaries, the collector + the six detector `.service`/`.timer` pairs +
`agentd` (observe), creates the config/state dirs (installing each detector's `config.json`
from its `config.example.json`), and generates **one** bearer token that it fans out to the
collector and every reporter so they all agree. A **release tarball** ships the binaries
prebuilt in `bin/`, so installing from one needs **no Go toolchain**; a **source clone** has
no `bin/`, so the installer builds the 8 Go modules itself (needs Go). It is review-first and
idempotent — re-running never clobbers an existing token (and heals a divergent reporter
token back to the shared one), and it **does not** arm response/enforce (those stay manual; see
[`agent/deploy/RESPONSE.md`](agent/deploy/RESPONSE.md) and
[`agent/deploy/ENFORCE.md`](agent/deploy/ENFORCE.md)).

**From a clone** (no `curl | sh` — read the script first; **needs Go** to build):

```sh
git clone https://github.com/mtclinton/defensive-suite
cd defensive-suite
less install.sh                 # review before running
sudo ./install.sh               # build + install the observe tier (needs root + Go)
# or, preview / stage without touching the system:
./install.sh --dry-run                       # print every action, change nothing
./install.sh --destdir /tmp/stage            # lay the whole tree under /tmp/stage
```

Useful flags: `--prefix DIR` (default `/usr/local`), `--version V` (default
`git describe`), `--from-bin` (force prebuilt binaries from `bin/`, never build),
`--uninstall` (keeps `/etc` + `/var/lib` data), `--uninstall --purge` (also removes
data; `--purge` requires `--uninstall`), `-h`. The collector serves the dashboard
locally at `http://127.0.0.1:8787/` once running.

**From a release tarball / AppImage** (**no Go needed** — binaries ship prebuilt in
`bin/`) — each tag publishes static **linux-amd64** and **linux-arm64** tarballs
(`bin/` + `deploy/` trees + `install.sh` + dashboard + docs) plus the desktop **console
AppImage** (amd64 only) and one `SHA256SUMS` over every release asset. Download the
tarball for your arch, the AppImage, and `SHA256SUMS` into the same directory, then:

```sh
# 1. Verify the downloads first, in the directory you downloaded them to.
sha256sum -c --ignore-missing SHA256SUMS
# 2. Extract the tarball and enter it.
tar xzf defensive-suite-<version>-linux-amd64.tar.gz
cd defensive-suite-<version>-linux-amd64
sudo ./install.sh                # the same installer, prebuilt binaries (no Go)
# 3. The console AppImage is a separate top-level asset (not inside the tarball).
cd ..
chmod +x defensive-suite-console-<version>-amd64.AppImage
./defensive-suite-console-<version>-amd64.AppImage
```

The console can **self-update** (opt-in, signature-verified) once the operator
runs keygen — it ships **inert** with a placeholder key and updates nothing by
default; the signing key stays a CI secret, never in the repo. See
[`console/UPDATING.md`](console/UPDATING.md).

Or via the top-level **Makefile**: `make build` (all 8 binaries into `./bin`),
`make install` (runs `install.sh`; pass `FLAGS="--destdir /tmp/x"`),
`make release-local` (per-arch tarballs in `./dist`), `make VERSION=v1.2.3 build` to pin
the injected version, `make clean`.

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