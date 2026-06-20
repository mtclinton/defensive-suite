# agentd — real-time agent (Phase 1, M1)

The continuous detection tier of the [endpoint-protection evolution](../docs/PHASE1_DESIGN.md).
The six tools are scheduled, point-in-time scans; **agentd** makes detection
*real-time*: it tails [Tetragon](https://tetragon.io)'s JSON event export,
evaluates each event against observe-mode rules, and forwards findings to the
[collector](../collector/) — so an exec or `bpf()` load shows up in seconds, not
on the next cron tick.

**M1 is observe-only — detection, no enforcement.** Blocking (Tetragon
`SIGKILL`/`Override`) and the manual-response actuators are later milestones
(M3/M4); see [`docs/PHASE1_DESIGN.md`](../docs/PHASE1_DESIGN.md). A single static
Go binary, standard library only.

```
Tetragon ──JSON export──▶ agentd ──findings──▶ collector ──▶ dashboard/console
 (exec, kprobe, bpf load)   rules               /ingest
```

## What it detects (M1 rules)

| Rule | Trigger | Severity | ATT&CK |
|------|---------|----------|--------|
| `realtime.exec` | exec from a staging dir (`/tmp`, `/dev/shm`, `/var/tmp`) | medium | T1059 |
| `realtime.exec` | fileless exec (`(deleted)` / `memfd:` binary) | high | T1620 |
| `realtime.bpf` | eBPF program load by a non-allowlisted loader | high | T1014 |
| `realtime.write` | write to a trust-path file (ld.so.preload / PAM / `authorized_keys` / sshd_config) | critical | T1574.006 · T1556.003 · T1098.004 |

These mirror the suite's existing detections, now evaluated live on the event stream.

## Run

```sh
make static
# point it at Tetragon's export and your collector (token via env):
AGENT_COLLECTOR_URL=http://127.0.0.1:8787/ingest \
AGENT_COLLECTOR_AUTH="Bearer $COLLECTOR_TOKEN" \
  ./bin/agentd run --tetragon-log /var/log/tetragon/tetragon.log
```

**Test it without Tetragon installed** — feed a recorded/synthetic event file:

```sh
agentd scan -file events.jsonl              # prints the findings, POSTs to the collector
agentd scan -file events.jsonl -no-post     # evaluate only, no forwarding
```

## Configuration (env `AGENT_*` or flags)

| Env | Meaning |
|-----|---------|
| `AGENT_TETRAGON_LOG` | Tetragon JSON export to tail (default `/var/log/tetragon/tetragon.log`) |
| `AGENT_COLLECTOR_URL` | collector `/ingest` endpoint (blank = don't forward) |
| `AGENT_COLLECTOR_AUTH` | `Authorization` header, e.g. `Bearer …` (env-only) |
| `AGENT_HOST` | report host label (default hostname) |
| `AGENT_BPF_ALLOWLIST` | comma list of legit eBPF-loader binaries (exact path, or a `dir/` prefix) |
| `AGENT_FLUSH_SECONDS` | how often the rolling finding set is POSTed in `run` mode |

## Deploy

- `deploy/tetragon/dsuite-observe.yaml` — a Tetragon TracingPolicy (observe mode)
  surfacing bpf-loads and trust-path writes. Enforcement is a one-line change,
  validated in a VM first.
- `deploy/systemd/agentd.service` — hardened long-running unit (observe-only:
  reads the Tetragon export + POSTs locally; all capabilities dropped).

Privileged steps (installing Tetragon, loading the policy) are shown in those
files for review — not run.

## Layout

```
agent/
├── main.go                 # `run` (tail) / `scan` (one-shot) / `version`
├── internal/
│   ├── tetragon/           # parse Tetragon JSON events → normalized form
│   ├── rules/              # event → findings (observe mode)
│   ├── pipeline/           # eval + rolling buffer + file tailer
│   ├── report/             # the shared Finding/Report + collector forward
│   └── config/             # defaults + AGENT_* env
└── deploy/                 # systemd unit + Tetragon observe policy
```
