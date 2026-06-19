# authwatch

A scheduled integrity-and-anomaly checker for the Linux **trust path**: PAM
modules, OpenSSH, `authorized_keys`, the dynamic linker, and the QLNX
fake-X11-lockfile pattern. It is the first tool of the
[defensive-suite](../README.md); see [`DESIGN.md`](DESIGN.md) for the spec and
[`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) for the threats it answers
(Velvet Ant PAM/OpenSSH backdoors, the QLNX RAT, the persistence layer of every
stealer).

A single static Go binary that shells out to `rpm`/`dpkg`/`debsums`, `aide`, and
`auditctl`, unifies their results, diffs them against an **off-host** baseline,
and emits findings to **journald and a webhook**.

## What it checks

| # | Check | Signal | Technique |
|---|-------|--------|-----------|
| 1 | `pkgverify` | auth binaries (`sshd`, `ssh`, `sudo`, libc, …) vs package checksums; masked to checksum-only to cut config noise | T1554 |
| 2 | `pam` | a `.so` under `*/security/` that **no package owns** (the highest-fidelity PAM-backdoor signal), plus tamper of owned modules | T1556.003 |
| 3 | `baseline` | SHA-256 of every auth-critical file vs an **off-host** known-good snapshot — catches tampering even when the package DB is also subverted | T1554 |
| 4 | `authkeys` | every `authorized_keys` entry vs an allowlist of attributable key fingerprints | T1098.004 |
| 5 | `preload` | populated `/etc/ld.so.preload`, `LD_PRELOAD` in shell init files and systemd unit `Environment=` | T1574.006 |
| 6 | `x11lock` | a `/tmp/.X*-lock` whose PID is not a running X server (QLNX fake lockfile) | T1036 |
| + | `auditd` | reports which trust-path audit watches are **not** loaded (read-only; never modifies auditd) | T1562.001 |
| + | `aide` | runs `aide --check` against the off-host AIDE database and summarizes drift (`--aide`) | T1565.001 |

A clean run reads: *all auth binaries match distro checksums; 0 unowned PAM
modules; 0 unattributable `authorized_keys`; `ld.so.preload` empty.* Any non-clean
line is a high-confidence compromise indicator.

## Build

```sh
make static      # CGO_ENABLED=0 → bin/authwatch, a single static binary
make test        # go test ./...
make vet         # go vet ./...
make release     # linux/amd64 + linux/arm64
```

Pure standard library — no external Go dependencies, so `go build ./...` works
offline and the binary is fully static.

## Usage

```sh
authwatch check                       # run all checks → journald + webhook + stdout
authwatch check --format json         # machine-readable report on stdout
authwatch check --aide                # also run `aide --check`
authwatch check --no-webhook          # skip the webhook (local/dev)
authwatch baseline -o PATH            # capture an off-host hash baseline
authwatch version
```

Exit codes: **0** clean · **2** a finding at medium or above (wire to systemd
`OnFailure`) · **1** operational error.

### Configuration

Defaults work out of the box; override via a JSON config (`--config`) and/or
environment. **Env wins, and secrets/host specifics come from env only** — nothing
sensitive is baked into source.

| Env | Meaning |
|-----|---------|
| `AUTHWATCH_WEBHOOK_URL` | webhook endpoint |
| `AUTHWATCH_WEBHOOK_AUTH` | `Authorization` header value (e.g. `Bearer …`) |
| `AUTHWATCH_BASELINE` | off-host baseline path |
| `AUTHWATCH_ALLOWLIST` | `authorized_keys` allowlist path |
| `AUTHWATCH_AIDE_CONFIG` | `aide --config` path |

See [`deploy/config.example.json`](deploy/config.example.json).

## Trust anchors live off-host

The baseline hash file and the AIDE database are the trust anchors. Store them on
an isolated host this machine can **write but not read or rewrite**; if they are
writable in place, an attacker rewrites them and they are worthless. authwatch
reads them through a configured path (e.g. a read-only mount) and never writes a
baseline during a `check` run.

## Deploy (privileged — review first)

Installing the systemd timer and the auditd watches changes system state.
authwatch ships them but loads nothing itself. The exact commands are in
[`deploy/README.md`](deploy/README.md).

## Output

- **journald**: one sd-daemon priority-prefixed line per finding (so journald
  assigns crit/err/warning/notice/info) plus a summary line — emitted to stderr,
  which journald captures under the systemd unit.
- **webhook**: the full report as JSON (`POST`), with the auth header from env.
- **stdout**: a human table (`--format text`) or the JSON report (`--format json`).

## Layout

```
authwatch/
├── main.go                 # CLI: check / baseline / version
├── internal/
│   ├── report/             # Finding/Report types + journald & webhook emit
│   ├── runner/             # command runner (real + fake for tests)
│   ├── config/             # defaults + file + env (env wins)
│   ├── pkgverify/          # rpm -V / dpkg -V / debsums + distro detection
│   ├── pam/                # unowned / tampered PAM modules
│   ├── baseline/           # off-host SHA-256 capture + diff
│   ├── authkeys/           # authorized_keys allowlist audit
│   ├── preload/            # ld.so.preload / shell init / systemd LD_PRELOAD
│   ├── x11lock/            # fake-X11-lockfile detection
│   ├── aide/               # aide --check wrapper
│   ├── auditd/             # auditctl -l watch-coverage report
│   └── check/              # orchestrator
└── deploy/                 # systemd, auditd rules, Sigma, config examples
```
