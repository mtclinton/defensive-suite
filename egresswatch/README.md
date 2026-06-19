# egresswatch

Per-process egress visibility plus passive-backdoor detection for a Linux
developer workstation. The threat cluster it answers: IronWorm-style Tor C2,
stage-two npm beaconing, exfil pipelines hiding in `deps`, and — the load-bearing
case — **BPFDoor/Symbiote magic-packet backdoors**. Most Linux setups watch
inbound and are blind to egress; egresswatch closes that gap two ways.

Part of the [defensive-suite](../README.md). Single static Go binary, **default
build is stdlib-only and builds/tests offline** — no external module requires, no
cgo, no clang. The eBPF parts are opt-in artifacts behind a build tag.

## What it does

**1. BPFDoor/Symbiote triage scanner** (`egresswatch triage`) — a pure-Go,
Rapid7-style triage over a configurable `/proc` root. It flags the documented
passive-backdoor markers:

- a process holding a **BPF filter on a raw / AF_PACKET socket** (the
  load-bearing signal — `/proc/net/packet` cross-referenced with each PID's
  `/proc/<pid>/fd` socket inodes);
- a **fileless / `(deleted)`** executable (`/proc/<pid>/exe`);
- **zero-byte mutex/lock files** matching the known single-instance guards;
- a thread **blocked in `packet_recvmsg`** (`/proc/<pid>/wchan` or `stack`).

**Zero processes with a BPF filter on a raw socket = no BPFDoor-class implant
present** — the design's verification statement, and what a clean run reports.

**2. Egress-allowlist evaluator** (`egresswatch egress`) — the OpenSnitch
allow/deny decision model expressed as **data plus a pure evaluator**. Given an
expected-egress allowlist (CIDRs / hostnames / ports for package mirrors,
Tailscale, known services) and the observed outbound connections (parsed from
`/proc/net/tcp{,6}`+`udp{,6}` by default, or `ss -tunp`), it flags every
connection **not on the allowlist**.

`egresswatch scan` runs both.

## The eBPF / IDS parts (shipped as artifacts, not built or loaded by default)

- **Magic-packet sensor** — an eBPF program (`bpf/magicpacket.bpf.c`) that hooks
  `setsockopt` and fires on `SO_ATTACH_FILTER` (the BPFDoor signature), with a
  `cilium/ebpf` loader (`bpf/loader.go`) and a `bpf2go` `//go:generate` directive.
  All of it is behind `//go:build linux && ebpf`, a tag the default build never
  sets — so the default `go build ./...` needs neither cilium/ebpf nor clang.
  `egresswatch sensor` runs it in an `-tags ebpf` build; the default binary
  prints build instructions instead.
- **Falco rule** — `deploy/falco/`: `setsockopt + SO_ATTACH_FILTER` on a socket.
- **Suricata + Zeek rules** — `deploy/{suricata,zeek}/`: the on-wire BPFDoor
  markers (hardcoded TCP sequence `1234`; technically invalid ICMP Echo code 1).
- **OpenSnitch** — `deploy/opensnitch/`: documented install-and-configure notes
  (eBPF backend, `DefaultAction: deny`, mirror the allowlist as allow rules).

egresswatch **never** compiles eBPF, loads it into the kernel, installs OpenSnitch
/ Falco / Suricata, or changes the system. All privileged commands are shown in
[`deploy/README.md`](deploy/README.md), not run.

## Usage

```sh
egresswatch scan    [flags]   # BPFDoor triage + egress-allowlist evaluation
egresswatch triage  [flags]   # only the /proc BPFDoor/Symbiote triage scan
egresswatch egress  [flags]   # only the egress-allowlist evaluation
egresswatch sensor  [flags]   # live eBPF magic-packet sensor (needs -tags ebpf, root)
egresswatch version

# flags: -config -webhook -allowlist -proc -conn-source(proc|ss) -format(text|json)
#        -no-webhook -timeout
```

Configuration is built-in defaults → optional JSON file (`-config`) → `EGRESSWATCH_*`
env vars (env wins). Secrets (the webhook auth token) come from the environment
only — never the config file, never source. Output goes to journald (sd-daemon
priority prefixes) and an optional webhook; the report is also printed as text or
JSON. **Exit codes: 0 clean, 2 findings at medium or above, 1 operational error.**

```sh
# Examples
egresswatch scan --allowlist /etc/egresswatch/egress.allow.json --no-webhook
egresswatch triage --proc /mnt/snapshot/proc --format json   # offline /proc snapshot
egresswatch egress --conn-source ss                          # parse `ss -tunp` instead of /proc
```

## Build

```sh
make build        # bin/egresswatch
make static       # CGO-free static binary (the deployable artifact)
make test vet     # default build: stdlib-only, offline-green
make release      # linux amd64 + arm64

# eBPF sensor (opt-in; needs clang + libbpf + BTF kernel; see deploy/README.md):
make generate-ebpf   # bpf2go: compile bpf/magicpacket.bpf.c
make build-ebpf      # go build -tags ebpf
```

## Layout

```
egresswatch/
├── main.go                       # flag subcommands: scan/triage/egress/sensor
├── sensor_stub.go                # default-build `sensor` placeholder
├── sensor_ebpf.go                # //go:build linux && ebpf — real sensor command
├── internal/
│   ├── report/                   # findings, severity, journald + webhook emit (shared pattern)
│   ├── runner/                   # external-command abstraction (ss) with a fake for tests
│   ├── config/                   # defaults → JSON file → env overrides
│   ├── triage/                   # BPFDoor/Symbiote triage: pure /proc parsers + scan
│   ├── egress/                   # allowlist evaluator + ss / /proc/net parsers + scan
│   └── check/                    # runs both checks, assembles the report
├── bpf/                          # //go:build linux && ebpf — C source, bpf2go directive, loader
└── deploy/                       # systemd, Falco, Suricata, Zeek, OpenSnitch notes, examples
```

Every parser in `triage` and `egress` is a pure function over fixture text,
table-tested without a live kernel. See [DESIGN.md](DESIGN.md) for the threat
context and [`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) for the suite-wide
threat-to-defense mapping.
