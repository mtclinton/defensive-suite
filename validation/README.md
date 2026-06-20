# validation — end-to-end harness (run on a throwaway Linux VM)

CI proves the suite **builds and unit-tests** on Linux. It cannot prove the EDR
actually **runs** against a real kernel — no finding has flowed through a live
Tetragon, and the enforce `SIGKILL` is unproven. This harness closes that gap.

> ⚠️ **THROWAWAY LINUX VM ONLY.** `validate.sh` arms Tetragon enforcement
> (SIGKILL on non-allow-listed eBPF loads) and, with `--with-response`, performs a
> **live kill** via agentd. It is the "validate in a VM" step from
> [`../agent/deploy/ENFORCE.md`](../agent/deploy/ENFORCE.md) — the privileged work
> the build and tests deliberately never do. It refuses to run on bare metal
> (`systemd-detect-virt` = `none`) unless you pass `--force-baremetal`, and it
> cleans up after itself (policies removed, processes stopped, temp dir deleted).

## What it proves

| Stage | Proves | How |
|-------|--------|-----|
| **2 detect** | M1 real-time pipeline, live | a synthetic eBPF load is reported as a `realtime.bpf` finding in the collector |
| **3 enforce** | M4 prevention, live | the same (non-allow-listed) load is **SIGKILLed**; Tetragon (allow-listed) survives |
| **4 respond** | M3 manual response, live | *(optional)* a throwaway process is killed via collector → agentd, and audited |

The negative control is [`loadbpf.c`](loadbpf.c) — it loads the most trivial valid
eBPF program. Under observe it loads (and is reported); under enforce it should die
by `SIGKILL` (exit 137). The allow-list is built from the **real on-disk paths** of
the running `tetragon` daemon (+ `cilium-agent`/`bpftool` if present), so arming
enforce can never kill Tetragon itself.

## Prerequisites (install first)

- A **running `tetragon` service with JSON file export** enabled (agentd consumes
  the export, default `/var/log/tetragon/tetragon.log`; override with
  `AGENT_TETRAGON_LOG`) and the **`tetra`** CLI — see
  [`../agent/deploy/ENFORCE.md`](../agent/deploy/ENFORCE.md) step (b).
- `go` (builds agentd + the collector), `cc` + kernel headers (`linux-libc-dev`,
  to compile `loadbpf.c`), `curl`, `nft`.

## Run

```sh
sudo ./validate.sh -y                 # stages 2 + 3 (detect + enforce)
sudo ./validate.sh -y --with-response # also stage 4 (the live kill)
# --keep            leave processes/policies/workdir up for inspection
# --force-baremetal skip the VM guard (only on a machine you can wipe)
```

Exit `0` = all checks passed; `1` = a check failed (per-stage `[PASS]`/`[FAIL]`
lines, and logs under the printed `/tmp/dsuite-validate.*` work dir). Without `-y`
it prints what it would do and exits — safe to run by accident.

## Cleanup

On any exit it removes the `dsuite-observe`/`dsuite-enforce` TracingPolicies, stops
the collector/agentd it started, flushes a leftover `dsuite_isolate` nft table if
present, and deletes its temp dir. Tetragon itself is left installed and running.
Re-runnable. (`--keep` skips cleanup so you can inspect state.)
