# credsentinel

A secret-exposure scanner **and** honeytoken tripwire for a Linux developer
workstation. It is the second tool of the [defensive-suite](../README.md); see
[`DESIGN.md`](DESIGN.md) for the spec and
[`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) for the threats it answers
(every credential stealer on the blog — atomic-lockfile, QLNX, easy-day-js stage
two — walks the same credential files; the Private-CISA leak is the at-rest risk).

A single static Go binary, pure standard library. Two halves:

1. **Exposure scanner.** Orchestrates `gitleaks` (fast regex) and `TruffleHog`
   (verifies whether a found credential is *live* against the provider API) over
   your repos, home directory, and the exact files the stealers harvest. When
   those tools are absent it falls back to a built-in stdlib scanner, so it still
   means something on a bare machine.
2. **Honeytoken tripwires.** A from-scratch honeytoken generator plants decoy
   credentials where a stealer looks, records each decoy's fingerprint + stat
   baseline, and detects a decoy being read or modified — a near-zero-false-
   positive breach indicator.

A clean run reads: **"0 live credentials in scanned paths; N honeytokens deployed
and quiet."**

## The exposure scanner

| Detector | Signal | Severity ceiling |
|----------|--------|------------------|
| `trufflehog` | calls the provider API; a **verified-live** credential | **Critical — rotate now** |
| `gitleaks` | a secret *shape* matched (not verified live) | High |
| `builtinscan` (fallback) | AWS keys (`AKIA…`), PEM `-----BEGIN … PRIVATE KEY-----`, provider tokens, generic high-entropy/long opaque tokens | High |

It covers the **exact stealer target list** (`targets` package) under your home,
file by file, with TruffleHog + the built-in scanner so the highest-value paths
are always checked even with no external tools installed:

`.npmrc` · `.pypirc` · `.git-credentials` · `.aws/credentials` · `.aws/config` ·
`.kube/config` · `.docker/config.json` · `~/.codex/auth.json` · `gh` CLI hosts ·
`.netrc` · SSH private keys (`id_*`, `*.pem`) · Vault token files.

Secrets are **redacted** in every finding (a short prefix + length), so a finding
never re-leaks the credential into journald or the webhook.

## The honeytokens

`credsentinel deploy` plants three decoys (all **invalid** credentials — they fail
closed if ever used) and records a manifest:

| Decoy | Default path | What it is |
|-------|--------------|------------|
| AWS key block | `~/.aws/credentials.bak` | `AKIA…DECOY` access key, dead secret |
| kubeconfig | `~/.kube/decoy.kubeconfig` | unroutable RFC-5737 TEST-NET cluster |
| DNS-token `.env` | `~/.config/app/.env.decoy` | a self-hosted Canarytoken hostname + dead DB/API creds |

`credsentinel watch` (alias `check`) compares each decoy's live state to the
manifest baseline:

- **atime advanced** past the baseline → something **read** it → **Critical**, assume compromise.
- **content changed** (sha mismatch) → decoy written/replaced → **Critical**.
- **decoy missing** → tripwire removed → **High**.
- otherwise → **"N honeytokens deployed and quiet"** (Info).

No legitimate process touches a decoy credential, so a trip is a near-zero-
false-positive breach indicator → rotate all credentials from a clean device and
escalate to `bpfsentry`'s offline check.

## Build

```sh
make static      # CGO_ENABLED=0 → bin/credsentinel, a single static binary
make test        # go test ./...
make vet         # go vet ./...
make release     # linux/amd64 + linux/arm64
```

Pure standard library — no external Go dependencies, so `go build ./...` works
offline and the binary is fully static.

## Usage

```sh
credsentinel scan                          # scan repos/home/stealer-targets → journald + webhook + stdout
credsentinel scan --with-honeytokens       # also fold the honeytoken watch into one report
credsentinel scan --format json            # machine-readable report on stdout
credsentinel scan --no-webhook             # skip the webhook (local/dev)
credsentinel scan --roots ~/src,~/work     # override scan roots
credsentinel deploy                        # plant honeytoken decoys + write the manifest
credsentinel watch                         # check the decoys for a trip (alias: check)
credsentinel version
```

Exit codes: **0** clean · **2** a finding at medium or above (a verified-live hit
or a honeytoken trip; wire to systemd `OnFailure`) · **1** operational error.

### Configuration

Defaults work out of the box; override via a JSON config (`--config`) and/or
environment. **Env wins, and secrets/token data come from env only** — nothing
sensitive is baked into source or serialized into a report.

| Env | Meaning |
|-----|---------|
| `CREDSENTINEL_WEBHOOK_URL` | webhook endpoint |
| `CREDSENTINEL_WEBHOOK_AUTH` | `Authorization` header value (e.g. `Bearer …`) — **env-only** |
| `CREDSENTINEL_SCAN_ROOTS` | comma-separated repo/home scan roots |
| `CREDSENTINEL_HOME` | home dir the stealer-target list resolves against |
| `CREDSENTINEL_HONEYTOKEN_DIR` | directory to plant decoys under |
| `CREDSENTINEL_MANIFEST` | decoy manifest path |
| `CREDSENTINEL_CANARY_HOST` | self-hosted Canarytoken DNS host woven into the `.env` decoy — **env-only** |

See [`deploy/config.example.json`](deploy/config.example.json) and
[`deploy/credsentinel.env.example`](deploy/credsentinel.env.example).

## Graceful degradation

A missing `gitleaks` or `trufflehog` is an **Info** finding, not an error — the
built-in fallback scanner carries the stealer-target paths. A missing manifest on
`watch` is Info ("run `deploy` first"). One failing detector never aborts the
others.

## Deploy (privileged — review first)

Installing the systemd timer and the auditd decoy watches changes system state.
credsentinel ships them but loads nothing itself. The exact commands — plus
self-hosting Thinkst Canarytokens behind Tailscale, and moving npm/PyPI/k8s/AWS
publishing to OIDC Trusted Publishers / workload identity to shrink the blast
radius — are in [`deploy/README.md`](deploy/README.md).

## Output

- **journald**: one sd-daemon priority-prefixed line per finding (crit/err/
  warning/notice/info) plus a summary line — emitted to stderr, which journald
  captures under the systemd unit.
- **webhook**: the full report as JSON (`POST`), auth header from env, redirects
  refused (a 3xx from the collector surfaces as an error, never followed).
- **stdout**: a human table (`--format text`) or the JSON report (`--format json`).

## Layout

```
credsentinel/
├── main.go                 # CLI: scan / deploy / watch (check) / version
├── internal/
│   ├── report/             # Finding/Report types + journald & webhook emit (shared shape)
│   ├── runner/             # command runner (real Exec + Fake for tests)
│   ├── config/             # defaults + file + env (env wins; secrets env-only)
│   ├── targets/            # the exact stealer-target credential file list + resolution
│   ├── gitleaks/           # gitleaks orchestrator + JSON report parser
│   ├── trufflehog/         # trufflehog orchestrator + NDJSON parser (verified=Critical)
│   ├── builtinscan/        # stdlib fallback: AWS keys / PEM / entropy heuristic
│   ├── honeytoken/         # from-scratch decoy generator + manifest + trip detection
│   └── scan/               # exposure-scanner orchestrator
└── deploy/                 # systemd timer, auditd decoy watches, Sigma, config examples
```
