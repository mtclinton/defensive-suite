# Phase 4 — false-positive soak runbook

**The hard gate before arming auto-response.** [`PHASE4_DESIGN.md`](PHASE4_DESIGN.md) §7.2
treats this as non-negotiable: *no measurement → no arming.* The auto-response decision
engine (increment 1) runs in **shadow** mode — it computes exactly what it *would* do and
emits a finding, but **never acts** (the bridge holds no executor; `canary`/`armed` are a
fatal preflight error in this build). This runbook is how you measure the real-world
false-positive rate of the one live-eligible action (**quarantine**) on *your* workload, so
the decision to ever arm it is made on data, not hope.

> **Safety.** Shadow mode is safe to run on a real workstation. It is the ordinary
> *observe* pipeline (Tetragon + the observe policy + agentd) plus a read-only decision
> layer; it loads **no** enforcement policy, makes **no** nftables/quarantine/kill changes,
> and touches **no** files or processes. It is *not* the "validate enforcement in a VM"
> path — nothing is enforced.

---

## 1. What you are measuring

The metric that gates arming (§7.2, #13):

> **distinct `(resolved-binary, action=quarantine)` auto-action *candidates* per day**, over
> a **≥14-day** window that includes your normal **build / CI / dev churn**.

Each time the gates (G1–G8) would select a **live quarantine**, the engine emits:

```
check    = realtime.autoresponse.shadow
title    = WOULD quarantine <resolved /proc target>
related  = [ "mode=shadow", "would_action=quarantine",
             "resolved_target=<live /proc/<pid>/exe realpath>",
             "dst=<ip:port>", "<gate outcomes>" ]
```

`would_action=alert-only` shadow findings (correlated events the policy would *not* act on)
are emitted too — they are **not** counted in the FP metric; only `would_action=quarantine`
is, because quarantine is the only action that ever goes live in v1.

A `realtime.autoresponse.throttled` finding means the auto-only rate budget tripped — a
flood/abuse signal, also worth watching (it must **never** disable manual response; that is
asserted by a unit test, but watch the rate anyway).

**Pass criterion:** over the soak, every distinct would-quarantine candidate is a **true
positive** (a real C2/exfil) or a clearly-understood event — i.e. **zero** would-quarantines
of a legitimate-but-staged binary (the design target is ~**≤1 / 30 days**). Build artifacts
in `/tmp` that dial `localhost` should **not** appear at all — gate **G7** makes loopback /
RFC1918 destinations ineligible; if they appear, that is itself a finding to investigate.

---

## 2. Prerequisites

- Tetragon installed with JSON file export, the `tetra` CLI, and the **observe** policy
  loaded — it must include the `tcp_connect` egress hook (correlation needs the egress
  events). See [`../agent/deploy/ENFORCE.md`](../agent/deploy/ENFORCE.md) step (b) and
  [`../agent/deploy/tetragon/dsuite-observe.yaml`](../agent/deploy/tetragon/dsuite-observe.yaml).
- The collector running (it receives + accumulates the shadow findings and serves the query
  API). See [`../agent/deploy/RESPONSE.md`](../agent/deploy/RESPONSE.md) / the installer.
- agentd built (`cd agent && CGO_ENABLED=0 go build -o agentd .`).
- A **representative host**: your actual daily-driver workload, or a box you run your real
  build/CI/dev on. The soak is only meaningful against real activity, including the noisy
  bits (go-test binaries, language servers, package managers, container runtimes).

---

## 3. Enable shadow mode (the only new setting)

`AGENT_AUTORESPONSE_MODE` defaults to **off** (no behavior change). Set it to **shadow**.
All other auto settings are optional and default-safe:

```sh
# in /etc/agentd/agentd.env (the observe unit's EnvironmentFile), or the run env:
AGENT_AUTORESPONSE_MODE=shadow          # off | dry-run | shadow  (canary/armed: fatal in this build)
# optional, shown with their defaults:
AGENT_AUTORESPONSE_RATE=3/300s          # auto-only budget; trips realtime.autoresponse.throttled
AGENT_AUTORESPONSE_STALE_TTL=5s         # G6 event-time freshness
AGENT_MGMT_SUBNETS=                     # G7: your mgmt/Tailscale CIDRs to treat as non-external
AGENT_AUTO_PROTECTED_PATHS=             # extra absolute exe paths that must never be a target
AGENT_AUTO_NEVER_QUARANTINE=            # extra path prefixes to exclude
# the auto-only disarm (distinct from the operator kill-switch /run/agentd/response.disabled):
AGENT_AUTORESPONSE_DISABLED=/run/agentd/autoresponse.disabled
```

> Set `AGENT_MGMT_SUBNETS` to your Tailscale/LAN ranges. G7 already excludes loopback +
> RFC1918 + CGNAT(100.64/10) + link-local; add anything else that is "internal" for you so a
> normal dial to an internal service is never counted as an external-egress candidate.

Then run the observe pipeline as usual — shadow rides along on the existing tail:

```sh
sudo systemctl restart agentd          # if running via the observe unit, after editing the env
# or, ad hoc:
sudo env $(grep -v '^#' /etc/agentd/agentd.env | xargs) \
  AGENT_TETRAGON_LOG=/var/log/tetragon/tetragon.log \
  AGENT_COLLECTOR_URL=http://127.0.0.1:8787/ingest AGENT_COLLECTOR_AUTH="Bearer <token>" \
  ./agentd run
```

Confirm it is in shadow (not off): `./agentd preflight` reports the mode, and a forced
`canary`/`armed` exits non-zero ("execution is not implemented in this build; max mode is
shadow") — the proof it cannot act.

---

## 4. Run it — ≥14 days, with real churn

Leave it running for **at least 14 days** and, crucially, **do your normal work on the host**
during the window: full build cycles, CI runs, the package managers and dev tools you
actually use. A soak on an idle box measures nothing. Re-run a representative build/CI batch
at least once so transient `/tmp` artifacts that dial out are exercised.

---

## 5. Measure (daily, and at the end)

The collector accumulates shadow findings. The candidate metric — **distinct would-quarantine
targets** seen so far:

```sh
# distinct would-quarantine candidates (the FP-soak numerator):
curl -s http://127.0.0.1:8787/api/findings \
 | jq -r '.[]
     | select(.check=="realtime.autoresponse.shadow")
     | select(any(.related[]?; . == "would_action=quarantine"))
     | (.related[] | select(startswith("resolved_target=")))' \
 | sort -u | tee /tmp/soak-quarantine-candidates.txt
echo "distinct would-quarantine candidates: $(wc -l < /tmp/soak-quarantine-candidates.txt)"
```

```sh
# context for each candidate (target + dst + title), to triage:
curl -s http://127.0.0.1:8787/api/findings \
 | jq -r '.[] | select(.check=="realtime.autoresponse.shadow")
     | select(any(.related[]?; . == "would_action=quarantine"))
     | [.title, ((.related[]|select(startswith("dst=")))), ((.related[]|select(startswith("resolved_target="))))] | @tsv'
```

```sh
# throttle events (flood/abuse signal — should be ~0 under normal load):
curl -s http://127.0.0.1:8787/api/findings \
 | jq '[.[] | select(.check=="realtime.autoresponse.throttled")] | length'
```

Snapshot the distinct count **daily** (cron the first command) so you get a per-day trend,
not just a total. (The collector's findings ring is capped; for a long/noisy soak also keep
the daily snapshots so nothing rolls off un-counted.)

---

## 6. Triage every candidate (per-action TP/FP — #23)

`undo_total` is a poor FP proxy, so judge each candidate by hand. For **each** entry in
`soak-quarantine-candidates.txt`, decide:

- **True positive** — a real malicious staged binary that connected to an external C2/exfil
  dst. Good: that is exactly what auto-quarantine is for.
- **False positive** — a *legitimate* binary that happened to run from a staging dir and dial
  an external host (a one-off dev tool, an installer, a self-updater run from `/tmp`). **This
  is the number that blocks arming.** Note what it was and why it tripped all of G1–G8.
- **Understood-and-acceptable** — a known internal tool you can add to
  `AGENT_AUTO_NEVER_QUARANTINE` / `AGENT_AUTO_PROTECTED_PATHS` or whose dst belongs in
  `AGENT_MGMT_SUBNETS`. Re-soak after tuning.

---

## 7. "Ready to arm" checklist

Do **not** proceed to the execution increment / `canary` until **all** hold:

- [ ] ≥14 days of soak **with real build/CI/dev churn** on a representative host.
- [ ] Distinct would-quarantine FP rate at/under the §7.2 target (~≤1 / 30 days — in practice
      **zero** FP would-quarantines of a legitimate binary over the window).
- [ ] Every would-quarantine candidate triaged TP / understood; tuning (`MGMT_SUBNETS`,
      `NEVER_QUARANTINE`, `PROTECTED_PATHS`) applied and re-soaked if any FP appeared.
- [ ] `realtime.autoresponse.throttled` is rare/absent under normal load (a chatty throttle
      means the rate budget or the trigger is mis-tuned for your host).
- [ ] **Egress source upgraded for `canary`+** — `PHASE4_DESIGN.md` Open Q #1 / §5 #3: the
      file-tail Tetragon source can only ever reach **shadow** trust (it is forgeable). The
      authenticated gRPC/socket export with peer auth is a precondition for arming, **not**
      later hardening.

Only then build the **execution increment** (responder lifecycle refactor + per-action
arming + reverse actuators + console push + fd-quarantine) behind `canary`, and start at the
narrowest live action.

---

## 8. Honest limits of this measurement

- **It measures false *positives*, not false *negatives*.** A low FP rate says nothing about
  attacker-induced suppression (correlation-state eviction, §5 #6) or a real C2 the file-tail
  source missed. The soak gates *safety of acting*, not *coverage*.
- **Shadow trust ceiling.** Because the Tetragon source is an unauthenticated file, a local
  attacker who can write that log can fabricate shadow findings; this is fine for *measuring*
  but is exactly why `canary`+ requires the authenticated export (checklist above).
- **The metric is the action's, not the signal's.** Count `would_action=quarantine` candidates
  (incl. CI/build churn), not raw `realtime.correlated` volume — the latter over-counts events
  the policy would never act on.
