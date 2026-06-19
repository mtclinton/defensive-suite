# bpfsentry

The flagship of the [defensive-suite](../README.md): an **offline eBPF-program
enumerator** and **out-of-band memory differ** for catching eBPF rootkits.

The threat is the structural blind spot. eBPF rootkits (IronWorm, atomic-lockfile,
QLNX, LinkPro, the BPFDoor lineage) hook `sys_bpf` to hide their own programs from
`bpftool` — defeating every live, on-box tool, including eBPF EDR. So the design
thesis is simple: **build at least one detection path that does not run on the
(possibly compromised) live kernel.** See [`DESIGN.md`](DESIGN.md) for the spec and
[`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) for the threats.

A single static Go binary. The **default build is standard-library only** — the
portable enumeration path shells out to `bpftool ... -j` and parses the JSON, so
`go build ./...` works offline with no external dependencies. The deeper
`cilium/ebpf` direct-enumeration path is an artifact behind the `linux && ebpf`
build tag, excluded from the default build. The out-of-band forensics ship as
Python under [`forensics/`](forensics/).

## Three layers

| Layer | What | Where | Can a `sys_bpf` hook lie to it? |
|-------|------|-------|--------------------------------|
| 1. Early-boot allowlist | enumerate before any agent/implant loads; diff later | `bpfsentry baseline` / `diff`, `deploy/systemd` | partly — captured before the implant |
| 2. Load-time alerting | catch the `bpf(BPF_PROG_LOAD)` the instant it fires | Tetragon / Tracee / auditd in `deploy/` | no — it fires before the implant can hide |
| 3. Out-of-band forensics | walk `prog_idr` in a memory image, off the live kernel | `forensics/` (Volatility 3 / LEMON) | **no — this is the part that can't be lied to** |

The single highest-signal finding in the whole suite: a program present in the
out-of-band view but **missing from the live `bpftool` view** — proof of a
`sys_bpf`-hooking rootkit. **Reinstall — do not clean.**

## What it does

- **`internal/enumerate`** — runs `bpftool prog|map|link show -j` via the runner
  and parses the JSON into a normalized inventory of programs/maps/links (name,
  type, tag, attach point, helpers where exposed). This is the portable, testable
  core. `DivergenceFromOOB` is a pure function comparing the live inventory
  against an out-of-band one.
- **`internal/baseline`** — captures the early-boot allowlist (named programs +
  attach points + a stable signature) and diffs a later enumeration against it.
  Flags: an unallowlisted program at a kprobe/tracepoint/LSM/XDP hook (High); an
  unnamed kretprobe/XDP program (Critical); any program using a suspicious helper
  — `bpf_override_return`, `bpf_probe_write_user`, `bpf_send_signal` (High).
- **`internal/status`** — reports detection-coverage posture; reduced visibility
  is itself a finding.

## Build

```sh
make static      # CGO_ENABLED=0 → bin/bpfsentry, a single static binary
make test        # go test ./...        (stdlib-only, offline)
make vet         # go vet ./...
make release     # linux/amd64 + linux/arm64
make ebpf-build  # build the cilium/ebpf direct path (-tags ebpf, Linux-only artifact)
make py-check    # python3 -m py_compile forensics/*.py
```

Pure standard library — no external Go dependencies, so `go build ./...` works
offline and the binary is fully static. `bpftool` must be on the host at runtime
for the portable enumeration path.

## Usage

```sh
bpfsentry baseline -o /mnt/anchor/allowlist.json   # capture the early-boot allowlist (off-host)
bpfsentry diff                                     # enumerate live + diff vs allowlist → journald + webhook
bpfsentry diff --oob oob-prog-idr.json             # also diverge against an out-of-band memory walk
bpfsentry diff --format json                       # machine-readable report on stdout
bpfsentry status                                   # detection-coverage / visibility posture
bpfsentry version
```

Exit codes: **0** clean · **2** a finding at medium or above (wire to systemd
`OnFailure`) · **1** operational error.

### Configuration

Defaults work out of the box; override via a JSON config (`--config`) and/or
environment. **Env wins, and secrets/host specifics come from env only** — nothing
sensitive is baked into source.

| Env | Meaning |
|-----|---------|
| `BPFSENTRY_WEBHOOK_URL` | webhook endpoint |
| `BPFSENTRY_WEBHOOK_AUTH` | `Authorization` header value (e.g. `Bearer …`) |
| `BPFSENTRY_BASELINE` | early-boot allowlist (off-host trust-anchor) path |
| `BPFSENTRY_BPFTOOL` | `bpftool` executable path |
| `BPFSENTRY_ALLOWED_LOADERS` | comma-list of legitimate program names |

See [`deploy/config.example.json`](deploy/config.example.json).

## The allowlist is an off-host trust anchor

The early-boot allowlist is the trust anchor. Capture it at known-good boot,
before any third-party agent loads (`deploy/systemd/bpfsentry-baseline.service`),
and store it on an isolated host this machine can **write but not read or rewrite**.
If it is writable in place, a rootkit rewrites it and the diff is worthless.

## The eBPF-tagged path (Linux-only artifact)

`internal/enumerate/direct_ebpf.go` (`//go:build linux && ebpf`) is a `cilium/ebpf`
direct walk of the kernel BPF tables — a richer live view that still reads the
live kernel and is therefore still defeated by a `sys_bpf` hook (which is *why*
layer 3 exists). It is **excluded from the default build** and pulls in the only
external dependency, added explicitly:

```sh
go get github.com/cilium/ebpf@latest
CGO_ENABLED=0 GOOS=linux go build -tags ebpf ./...
```

## Out-of-band forensics (privileged — documented, not run)

[`forensics/`](forensics/) ships Python wrappers for the Volatility 3 `prog_idr`
walk and LEMON / `virsh dump --memory-only` acquisition, plus `oob_parser.py`
which emits the exact JSON shape `bpfsentry diff --oob` ingests. Those acquisition
and Volatility commands are privileged; the scripts **print** them and run nothing.

## Deploy (privileged — review first)

bpfsentry ships the systemd units, the Tetragon TracingPolicy, the Tracee policy,
the auditd rule, and a Sigma rule, but loads nothing itself. The exact commands
are in [`deploy/README.md`](deploy/README.md).

## Layout

```
bpfsentry/
├── cmd/bpfsentry/          # CLI: baseline / diff / status / version
├── internal/
│   ├── report/             # Finding/Report types + journald & webhook emit
│   ├── runner/             # command runner (real + fake for tests)
│   ├── config/             # defaults + file + env (env wins)
│   ├── enumerate/          # bpftool JSON → normalized inventory + divergence
│   │   └── direct_ebpf.go  #   //go:build linux && ebpf — cilium/ebpf artifact
│   ├── baseline/           # early-boot allowlist capture + diff
│   └── status/             # detection-coverage / visibility posture
├── deploy/                 # systemd, Tetragon, Tracee, auditd, Sigma, config
└── forensics/              # Python: Volatility prog_idr walk + acquisition + parser
```
