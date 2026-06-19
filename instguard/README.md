# instguard

A supply-chain **install-time guard** for npm and AUR. It intercepts the moment
of maximum risk — `npm install` / an AUR build — because the modern poisoned-
dependency waves (Mastra/easy-day-js, IronWorm, Miasma/Shai-Hulud, codexui-
android, Nx Console, TrapDoor, the AUR atomic-lockfile cross-registry hop) almost
all execute their payload at install time, **before any `import`**. instguard is
the second tool of the [defensive-suite](../README.md); see [`DESIGN.md`](DESIGN.md)
for the spec and [`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) for the
threats it answers.

A single static Go binary (standard library only — no external deps, builds
offline). It reads project files, queries OSV.dev, and emits a per-package
**verdict** plus findings to **journald and a webhook**. It never installs,
builds, or executes any package or build script.

## What it checks

| # | Check | Signal | Technique |
|---|-------|--------|-----------|
| 1 | `lockfile` | a dep declared in `package.json` but absent from `package-lock.json` (the gap a payload lives in); a missing lock; multiple competing lockfiles | T1195.001 |
| 2 | `hooks` | install lifecycle scripts (`preinstall`/`install`/`postinstall`/`prepare`) that `curl\|sh`, `node -e`, `eval`, decode base64/atob blobs, or set `NODE_TLS_REJECT_UNAUTHORIZED=0` | T1059 |
| 3 | `osv` | an OSV.dev advisory on a pinned `(package, version)` — a `MAL-` (malicious-package) id is **Critical/BLOCK**, any other advisory is Medium | T1195.002 |
| 4 | `cooldown` | a pinned version published inside the release-age window (default 3 days — most malicious uploads earn a `MAL-` classification within ~3 days) | T1195.002 |
| 5 | `aur` | unexpected/obfuscated `npm`/`bun`/`npx`/`pnpm` invocations or `curl\|sh` in `PKGBUILD` / `.install` / `.hook` (hex/`\x`/quoting de-obfuscated **as data**, never executed) | T1195.001 |
| + | `audit` | (`instguard audit`) a post-install pass over `~/.npm/_logs` for any lifecycle script that actually ran | T1059 |

Each package gets a verdict — **SAFE** / **REVIEW** / **BLOCK** — with the
reason. `instguard check` exits **1** on any BLOCK, so it is a drop-in CI gate.

## Build

```sh
make static      # CGO_ENABLED=0 → bin/instguard, a single static binary
make test        # go test ./...
make vet         # go vet ./...
make release     # linux/amd64 + linux/arm64
```

Pure standard library — `go build ./...` works offline and the binary is fully
static.

## Usage

```sh
instguard check                          # vet ./ → verdicts to journald + webhook + stdout
instguard check --project /srv/app       # vet a specific project
instguard check --format json            # machine-readable report on stdout
instguard check --offline                # skip the OSV network query (static checks only)
instguard check --release-meta meta.json # supply publish dates for the cooldown
instguard check --no-webhook             # skip the webhook (local/dev)
instguard audit                          # post-install: scan ~/.npm/_logs for hooks that ran
instguard version
```

### Exit codes

| Code | Meaning |
|------|---------|
| **0** | clean — every package SAFE |
| **1** | operational error, **or** one or more **BLOCK** verdicts (the CI gate) |
| **2** | a finding at medium or above (REVIEW-level risk) — wire to systemd `OnFailure` if you want it loud |

A BLOCK takes precedence over exit 2, so a hard block is unambiguous to CI.

### The safe install workflow

instguard is the vetting step in a deliberately script-free install (documented
in [`deploy/README.md`](deploy/README.md), **not** run by instguard):

```sh
npm ci --ignore-scripts      # install against the lock with scripts DISABLED
instguard check --project .  # vet drift / hooks / MAL- advisories / AUR
npm audit signatures         # require SLSA provenance / publish attestations
```

## OSV, offline, and graceful degradation

The OSV.dev client is built behind an injectable HTTP transport, so it is tested
with `httptest` and runs **offline** without failing: `--offline` (or no network)
turns the OSV query into an Info "skipped" note rather than an error, and every
static check (lockfile, hooks, cooldown, AUR) still runs. A missing `npm` binary
is likewise an Info "tool absent", never a crash.

### Configuration

Defaults work out of the box; override via a JSON config (`--config`) and/or
environment. **Env wins, and the webhook auth token comes from env only** —
nothing sensitive is baked into source.

| Env | Meaning |
|-----|---------|
| `INSTGUARD_WEBHOOK_URL` | collector webhook endpoint |
| `INSTGUARD_WEBHOOK_AUTH` | `Authorization` header value (e.g. `Bearer …`) |
| `INSTGUARD_PROJECT_DIR` | project directory to scan |
| `INSTGUARD_OSV_URL` | OSV.dev query endpoint (or a mirror) |
| `INSTGUARD_COOLDOWN_DAYS` | release-age cooldown in days (default 3) |
| `INSTGUARD_NPM_LOGS_DIR` | npm logs dir for `instguard audit` |
| `INSTGUARD_OFFLINE_OSV` | `1` to skip the OSV network query |

See [`deploy/config.example.json`](deploy/config.example.json).

## Output

- **journald**: one sd-daemon priority-prefixed line per finding (so journald
  assigns crit/err/warning/notice/info) plus a summary line — emitted to stderr,
  which journald captures under the systemd unit.
- **webhook**: the full report (findings + verdicts) as JSON (`POST`), auth header
  from env, redirects refused so a spoofed collector can't harvest the token.
- **stdout**: a human table (`--format text`) or the JSON report (`--format json`).

## Deploy (privileged — review first)

A hardened systemd timer scans a configured project periodically; a CI/pre-commit
gate fails the build on a BLOCK; a Sigma rule catches the install-hook RCE at
runtime. instguard ships them but loads nothing itself. See
[`deploy/README.md`](deploy/README.md).

## Layout

```
instguard/
├── main.go                 # CLI: check / audit / version
├── internal/
│   ├── report/             # Finding/Report/Verdict types + journald & webhook emit
│   ├── runner/             # command runner (real + fake for tests)
│   ├── config/             # defaults + file + env (env wins)
│   ├── lockfile/           # package.json vs package-lock.json drift
│   ├── hooks/              # install-hook scanner (curl|sh, node -e, eval, base64, TLS-off)
│   ├── osv/                # OSV.dev MAL- query (injectable HTTP client)
│   ├── cooldown/           # release-age cooldown (pure, injected "now")
│   ├── aur/                # PKGBUILD/.install/.hook parse + de-obfuscation (data only)
│   ├── auditlog/           # ~/.npm/_logs post-install audit
│   ├── verdict/            # SAFE/REVIEW/BLOCK roll-up
│   └── check/              # orchestrator
└── deploy/                 # systemd, CI gate, Sigma, config examples
```
