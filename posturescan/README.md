# posturescan

Measures — and **dry-run** remediates — the kernel and container **hardening
posture** the [defensive-suite](../README.md) threat cluster turns on: the
sysctls and kernel settings that defeat kernel LPE + container escape (Copy Fail
/ DirtyDecrypt / Dirty Frag), the **ssh-keysign-pwn** ptrace race, and the whole
`bpf()` eBPF-rootkit attack surface. See [`DESIGN.md`](DESIGN.md) for the spec
and [`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) for the threats.

A single static Go binary (standard library only). It reads sysctls from a
`/proc/sys` root (falling back to `sysctl -a`), reads kernel lockdown, audits
systemd units and container specs for stray capabilities, scores rootless-Podman
posture, optionally wraps Lynis / OpenSCAP / `systemd-analyze security`, and
emits findings to **journald and a webhook** plus a before/after **hardening
index** and a per-sysctl **OK/DIFFERENT** table.

## What it checks

| # | Check | Signal | Technique |
|---|-------|--------|-----------|
| 1 | `sysctl` | per-key OK/DIFFERENT vs the target profile: `unprivileged_bpf_disabled` (want 1\|2), `yama.ptrace_scope` (want 2 — the ssh-keysign-pwn fix), `kptr_restrict`, `dmesg_restrict`, `modules_disabled`, `module.sig_enforce` | T1068 |
| 1 | `lockdown` | `kernel.lockdown` confidentiality (read `/sys/kernel/security/lockdown`) — hidden processes/modules reappear under it | T1014 |
| 2 | `caps` | systemd units + OCI/`podman inspect` specs granting `CAP_BPF` / `CAP_SYS_ADMIN` (etc.) to anything that isn't a known eBPF tool — a stray `CAP_BPF` is the rootkit primitive | T1068 |
| 3 | `podman` | rootless, `--cap-drop=all`, no-new-privileges, seccomp present, read-only rootfs, user namespaces → a 0–100 score from a container spec | — |
| 4 | `lynis` / `oscap` / `systemd-analyze` | Lynis hardening index, OpenSCAP XCCDF pass rate, per-service exposure scores (with `--wrap-tools`) | — |

The sysctl read+diff is a **pure function over an injected value source** (a
`/proc/sys`-style dir or canned `sysctl -a` text), so the tests never depend on
the host kernel. Every external tool **degrades gracefully**: lynis/oscap/
systemd-analyze absent → an Info "not installed" finding, never a hard failure.

Goal state (DESIGN.md): `unprivileged_bpf_disabled=2`, `ptrace_scope=2`,
`lockdown=confidentiality`, module signing enforced, **no stray `CAP_BPF`**.

## Build

```sh
make static      # CGO_ENABLED=0 → bin/posturescan, a single static binary
make test        # go test ./...
make vet         # go vet ./...
make release     # linux/amd64 + linux/arm64
```

Pure standard library — no external Go dependencies; `go build ./...` works
offline and the binary is fully static.

## Usage

```sh
posturescan scan                      # OK/DIFFERENT table + hardening index → journald + webhook + stdout
posturescan scan --format json        # machine-readable report on stdout
posturescan scan --wrap-tools         # also run lynis / oscap / systemd-analyze security
posturescan scan --spec ./config.json # also audit + score a container spec (repeatable)
posturescan scan --no-webhook         # skip the webhook (local/dev)
posturescan remediate                 # DRY RUN: print the sysctl.d drop-in + commands
posturescan version
```

Exit codes: **0** clean · **2** drift at medium or above (wire to systemd
`OnFailure`) · **1** operational error.

### Remediation is strictly dry-run

`posturescan remediate` **never** writes to `/etc`, runs `sysctl`, or modifies
the system. It reads the current values, then **prints** the
`/etc/sysctl.d/99-posturescan.conf` drop-in content and the `sudo sysctl
--system` command for you to review and run yourself. Kernel lockdown and module
signing are boot-time settings, not runtime sysctls, so it emits a kernel-cmdline
note for those instead of a drop-in line.

### Configuration

Defaults work out of the box; override via a JSON config (`--config`) and/or
environment. **Env wins, and secrets/host specifics come from env only.**

| Env | Meaning |
|-----|---------|
| `POSTURESCAN_WEBHOOK_URL` | webhook endpoint |
| `POSTURESCAN_WEBHOOK_AUTH` | `Authorization` header value (e.g. `Bearer …`) |
| `POSTURESCAN_PROC_SYS_ROOT` | `/proc/sys`-style root to read sysctls from |
| `POSTURESCAN_LOCKDOWN_PATH` | kernel lockdown state file |
| `POSTURESCAN_PROFILE` | target sysctl profile path |
| `POSTURESCAN_CONTAINER_SPECS` | comma-separated container spec paths |

See [`deploy/config.example.json`](deploy/config.example.json) and the target
profile [`deploy/profiles/hardening-target.conf`](deploy/profiles/hardening-target.conf).

## Output

- **journald**: one sd-daemon priority-prefixed line per finding plus a summary
  line — emitted to stderr, which journald captures under the systemd unit.
- **webhook**: the full report as JSON (`POST`, no-redirect), auth header from env.
- **stdout**: the before/after hardening index, the per-sysctl OK/DIFFERENT
  table, and a findings table (`--format text`) or the JSON report (`--format json`).

## Deploy (privileged — review first)

posturescan ships a systemd timer/service, the target profile, and the example
`/etc/sysctl.d` drop-in, but **installs nothing itself**. The exact commands are
in [`deploy/README.md`](deploy/README.md).

## Layout

```
posturescan/
├── main.go                 # CLI: scan / remediate / version
├── internal/
│   ├── report/             # Finding/Report/Posture types + journald & webhook emit
│   ├── runner/             # command runner (real + fake for tests)
│   ├── config/             # defaults + file + env (env wins)
│   ├── sysctl/             # read /proc/sys + parse `sysctl -a`; pure diff + index
│   ├── caps/               # CAP_BPF/CAP_SYS_ADMIN audit (systemd units + specs)
│   ├── podman/             # OCI/podman-inspect parse + rootless posture score
│   ├── tools/              # lynis / oscap / systemd-analyze wrappers
│   ├── remediate/          # DRY-RUN sysctl.d drop-in generator
│   └── check/              # orchestrator (assembles the report + posture)
└── deploy/                 # systemd, target profile, example drop-in, config
```
