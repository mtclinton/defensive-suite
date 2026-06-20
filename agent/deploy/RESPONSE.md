# agentd — manual response (M3) enablement

> ⚠️ **REVIEW BEFORE RUNNING. VALIDATE IN A VM, NEVER FIRST ON THE DAILY DRIVER.**
> Every command below is shown for you to read, not auto-run. Enabling response
> arms a privileged primitive (kill / isolate / quarantine / revoke-key /
> block-hash). Nothing here is executed by the build or the tests.

## The two safety gates (default state = harmless)

1. **`ResponseEnabled` defaults `false`** → the Responder runs in **DRY-RUN**: it
   validates and audits the request and returns *what it would do*, but the
   `Executor` is never called. The inert `FakeExecutor` is wired in dry-run, so
   even a coding slip cannot reach the real one.
2. The **`Executor` is an interface.** `RealExecutor` (the side-effecting
   `syscall.Kill` / `nft` / `chattr` / `authorized_keys` / `fapolicyd` impl) is
   only constructed when `--enable-response` is set. All tests use
   `FakeExecutor`; `RealExecutor` is shipped but never invoked in CI.

Leaving the flags off ⇒ agentd serves the response API in dry-run (or not at
all, if no socket/token is set) and **cannot perform a destructive action.**

## Guardrails (pure, enforced before any execution, then re-checked in RealExecutor)

| Action       | Refused when … |
|--------------|----------------|
| `kill`       | target not a numeric PID; PID ≤ 1 (init/kthreads); the agent's own PID |
| `isolate`    | target names a management/keep-up interface (would self-lock-out) — `lo` is always protected |
| `quarantine` | target under `/proc`,`/sys`,`/dev`, the critical denylist (`/bin`,`/sbin`,`/usr`,`/lib*`,`/boot`,`/etc`), or `/` itself; relative paths |
| `revoke-key` | target is not an `authorized_keys[2]` file; missing `fingerprint` arg (the file is backed up and never emptied) |
| `block-hash` | target is not a 64-hex SHA-256 |

Every request is written to an **append-only JSON-lines audit log**
(`<state-dir>/response-audit.jsonl`) at both *intent* and *result* stages.

## 1. Response token (env-only, never a flag → not in the process table)

```sh
sudo install -d -m 0750 /etc/agentd
sudo install -m 0600 deploy/agentd-response.env.example /etc/agentd/agentd.env
# set AGENT_RESPONSE_TOKEN to a long random value:
#   openssl rand -hex 32
sudoedit /etc/agentd/agentd.env
```

## 2. Enable response — REVIEW; this arms privileged actions

```sh
# Dry-run first (default): the socket serves, but NOTHING is executed.
sudo AGENT_RESPONSE_TOKEN=… agentd run \
  --response-socket /run/agentd.sock

# Go LIVE only after validating in a VM. Requires root (kill/nft/chattr/fapolicyd).
sudo AGENT_RESPONSE_TOKEN=… agentd run \
  --response-socket /run/agentd.sock \
  --enable-response
```

The socket is created `0600` (root-only). agentd refuses to serve it without
`AGENT_RESPONSE_TOKEN` set — a privileged socket with no auth must not start.

## 3. Point the collector at the socket (so the console can request actions)

The unprivileged collector proxies `POST /api/respond` → the agentd socket and
records every request+result. It never performs a privileged action itself.

```sh
# in /etc/collector/collector.env (0600):
COLLECTOR_AGENT_SOCKET=/run/agentd.sock
COLLECTOR_RESPONSE_TOKEN=<same value as AGENT_RESPONSE_TOKEN>
```

`/api/respond` is **absent** unless both are set, and **fails closed** (503) if
the token is empty — the collector never proxies privileged actions by accident.

## 4. Host pre-reqs for LIVE mode (don't assume; validate in a VM)

- `nft` (nftables) present — for `isolate` (installs an egress-drop table,
  reversible: `nft delete table inet dsuite_isolate`).
- `chattr` present — for `quarantine` (`+i` immutable; reversible).
- `fapolicyd` + `fapolicyd-cli` present — for `block-hash` (deny rule by
  SHA-256; reversible: remove the rule file + `fapolicyd-cli --update`).
- agentd running as root with the right `CapabilityBoundingSet` for the actions
  you actually enable. `kill` is irreversible by nature; the rest return an
  `undo` string.

## Reversibility summary (returned in each `Result.Undo`)

| Action       | Reversible? | Undo |
|--------------|-------------|------|
| kill         | no          | — |
| isolate      | yes         | `nft delete table inet dsuite_isolate` |
| quarantine   | yes         | `chattr -i <q> && mv <q> <orig>` |
| revoke-key   | yes         | restore from the `.dsuite.bak` backup |
| block-hash   | yes         | remove the fapolicyd rule + reload |
