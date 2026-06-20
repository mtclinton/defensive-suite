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

## 2. Enable response — via the LEAST-PRIVILEGE systemd unit (REVIEW; arms actions)

> ⚠️ Do **not** run the armed daemon as interactive full root. The shipped
> `systemd/agentd-response.service` runs it with **only the capabilities the
> actuators need** (not full root), keeps the observe unit's sandbox, and wires
> the **kill-switch + rate-limit brakes**. **Review the unit, then VM-first.**

```sh
# Install the least-privilege unit (SHIPPED, not auto-installed). REVIEW it first.
sudo install -m 0644 deploy/systemd/agentd-response.service \
  /etc/systemd/system/agentd-response.service
sudo systemctl daemon-reload

# Enable + start the ARMED, least-privilege response daemon (VM-FIRST):
sudo systemctl enable --now agentd-response
sudo systemctl status agentd-response          # confirm it came up
journalctl -u agentd-response -f               # watch the audit/startup lines
```

The unit's `ExecStart` is `agentd run --response-socket /run/agentd/agentd.sock
--enable-response`. The socket is created `0600` (root-only) under the unit's
`RuntimeDirectory` (`/run/agentd`). agentd refuses to serve it without
`AGENT_RESPONSE_TOKEN` set — a privileged socket with no auth must not start.

### Capability → actuator mapping (why it is NOT full root)

| Capability | Actuator(s) | Why |
|------------|-------------|-----|
| `CAP_KILL` | `kill` | `SIGKILL` a process we don't own |
| `CAP_NET_ADMIN` | `isolate` | `nft` add table/chain/rule (egress drop) |
| `CAP_LINUX_IMMUTABLE` | `quarantine` | `chattr +i` the quarantined file |
| `CAP_DAC_OVERRIDE` | `revoke-key`, `block-hash`, `quarantine` | write root/other-owned `authorized_keys`, write `/etc/fapolicyd`, rename/chmod files we don't own |
| `CAP_FOWNER` | `quarantine`, `revoke-key` | chmod/chattr files whose owner isn't us |
| `CAP_DAC_READ_SEARCH` | observe pipeline | read the root-owned Tetragon export |

Notable sandbox trade-off: **`ProtectHome=false`** — `revoke-key` must edit
`/root/.ssh` and `/home/*/.ssh`. If you don't use `revoke-key`, tighten
`ProtectHome` and drop `CAP_DAC_OVERRIDE`. See the unit's inline comments for
every deviation from the observe unit (`agentd.service`).

### Two brakes on the weaponizable primitive (set in the unit / env)

- **Kill-switch** (`AGENT_RESPONSE_KILLSWITCH`, default
  `/run/agentd/response.disabled`): `touch` it to **instantly disarm ALL
  response** — every request is refused (even live) and audited — **without
  restarting** the daemon. `rm` it to re-arm.

  ```sh
  sudo touch /run/agentd/response.disabled   # disarm now (no restart)
  sudo rm    /run/agentd/response.disabled   # re-arm
  ```

- **Rate limit** (`AGENT_RESPONSE_RATE`, default `10/60s`): caps **live**
  executions per window (dry-run is free). A hijacked response surface cannot
  become a rapid mass-kill / mass-isolate DoS — the (N+1)th action in the window
  is refused and audited.

### Dry-run preview (optional, no destructive action)

To preview without arming, run the unit's command **without** `--enable-response`
(or set `AGENT_ENABLE_RESPONSE=0` in the env file): the socket serves, the brakes
apply, and the responder returns *what it WOULD do*, audited, but the executor is
never called.

## 3. Point the collector at the socket (so the console can request actions)

The unprivileged collector proxies `POST /api/respond` → the agentd socket and
records every request+result. It never performs a privileged action itself.

```sh
# in /etc/collector/collector.env (0600):
# Must match agentd-response.service's --response-socket (RuntimeDirectory /run/agentd).
COLLECTOR_AGENT_SOCKET=/run/agentd/agentd.sock
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
- agentd running under `agentd-response.service` with the least-privilege
  `CapabilityBoundingSet` above (NOT full root) for the actions you actually
  enable. `kill` is irreversible by nature; the rest return an `undo` string.

## Reversibility summary (returned in each `Result.Undo`)

| Action       | Reversible? | Undo |
|--------------|-------------|------|
| kill         | no          | — |
| isolate      | yes         | `nft delete table inet dsuite_isolate` |
| quarantine   | yes         | `chattr -i <q> && mv <q> <orig>` |
| revoke-key   | yes         | restore from the `.dsuite.bak` backup |
| block-hash   | yes         | remove the fapolicyd rule + reload |
