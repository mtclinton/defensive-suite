# Phase 4 — Auto-Response Un-Gating (gated machinery)

Status: **built + unit-tested, RUNTIME-INERT in this build.** Auto-response still cannot
fire on any host running this build. This increment builds the decision→execution
machinery and its safety rails, gated behind a recorded FP-soak attestation, a grace/veto
window, and a lockout watchdog — but the runtime arm path remains **refused** because two
rails (the agentd→console push channel and the authenticated gRPC/socket Tetragon export)
are still unbuilt. The new code is therefore exercised **only by unit tests**, never by a
running agentd. See [PHASE4_DESIGN.md](PHASE4_DESIGN.md) and
[PHASE4_FP_SOAK.md](PHASE4_FP_SOAK.md).

## 1. Goal & non-goal

- **Goal:** build the bridge→Respond wire, the grace/veto (CANCEL) queue, and the §4.3
  lockout watchdog + auto-rollback, and convert the arm gate from "always refuse
  canary/armed" to "refuse unless a valid FP-soak pass attestation is present (and the
  remaining rails are built)". Everything unit-tested, fail-closed.
- **Non-goal:** arming, enabling enforcement, or running agentd live. The default mode
  stays `shadow`. Nothing in this increment lets a running agentd take a destructive
  action. Arming is validated in a VM, never on a daily driver, and only after the FP-soak
  passes — neither is performed here.

## 2. Safety architecture — the Bridge stays a pure decider

The pre-existing **structural** invariant is preserved, not weakened:

> The `Bridge` (decision engine) holds **no** Executor/Responder reference and is
> structurally incapable of acting. `TestBridgeHasNoExecutorField` and
> `TestBridgeNeverExecutesEvenWithEverythingConstructed` remain **unchanged and passing.**

The decision→execution wire lives in a **separate** component, `AutoActuator`
(`autoactuator.go`), constructed at the agent lifecycle layer (main.go) — *not* inside the
Bridge. The Bridge still only decides and emits `realtime.autoresponse.shadow` findings.
The AutoActuator is the only thing that holds a `*Responder`, and it is the only new path
from a decision to an action. This keeps the strongest guarantee (the decision engine
cannot act) intact and isolates the dangerous wire in one heavily-gated, separately-tested
unit.

### 2.1 Defense-in-depth gate chain (every gate fail-closed)

A decision becomes an action only if **all** of these hold, checked in order:

1. **Mode** — `canary` or `armed`. Default is `shadow`; `off`/`dry-run`/`shadow` never
   reach the AutoActuator's execute path (it returns the shadow finding and stops).
2. **Arm gate (preflight, fatal)** — `ArmingPreconditions` returns empty. Requires a valid
   **soak-pass attestation** AND an authenticated export AND all `deferredUnmet` rails
   built. **In this build `deferredUnmet` is non-empty (console push + authenticated
   export), so canary/armed are still fatally refused at startup** → the AutoActuator is
   never even constructed in a canary/armed agentd. This is the runtime-inert property.
3. **Soak attestation** — a machine-checked artifact proving the FP-soak passed (§3).
4. **Per-action dry-run default** — `Request.DryRun` defaults to true unless the operator
   explicitly armed the specific action (§4.4); a dry-run never calls `Execute`.
5. **Grace/veto window** — the action is enqueued for `AGENT_AUTORESPONSE_GRACE` (incl.
   quarantine, #14); an operator CANCEL within the window aborts (and runs the inverse if
   already applied) (§4).
6. **Execute** — through the existing `Responder` (kill-switch, rate-limit, audit, guards
   all already enforced there).
7. **Lockout watchdog + auto-rollback** — after a live action, a positive operator-lockout
   signal triggers auto-undo of journaled actions (§5).
8. **Standing brakes** — the auto-disarm latch, the shared kill-switch, and the auto-rate
   budget continue to apply.

### 2.2 The runtime-inert property (why nothing fires in this build)

`ArmingPreconditions(canary|armed, …)` still returns a non-empty list because
`deferredUnmet` retains the two genuinely-unbuilt rails:

- the agentd→console push channel for notify-and-undo (§4.6) — without it the grace/veto
  has no operator to notify, so "notify-and-undo" is not a real rail;
- the authenticated gRPC/socket Tetragon export — the file-tail source can only reach
  shadow (§5 #3).

Startup is therefore fatally refused for canary/armed, exactly as before — the
`AutoActuator` is constructed **only** by unit tests that inject a `*Responder` and force
the mode. The wire, grace queue, and watchdog have **no runtime caller** in this build.
`TestArmingStillRefusedInThisBuild` asserts this and must stay green until those rails land.

## 3. Soak-pass attestation (the new arm precondition)

`AGENT_AUTORESPONSE_SOAK_ATTESTED` points to a soak attestation file. `armgate` validates
it machine-checkably; any failure ⇒ the precondition is unmet ⇒ refusal (fail-closed). A
**pass** requires all of:

- `schema: dsuite.soak.attestation/v1` and a parseable JSON body;
- `duration_days >= 14` (the soak ran long enough on real churn);
- `distinct_would_quarantine <= 0` over the window — i.e. **zero** distinct
  `(resolved_target, would_action=quarantine)` candidates that were not triaged away
  (matches `soak-report.sh` §5; one unexplained FP ⇒ fail);
- `unexplained_fp == 0` (every shadow would-quarantine was triaged TP/understood);
- `generated_at` within `attestation_max_age` (default 30d) of now (stale soak ⇒ refuse);
- `host_class` matches the arming host's class (a workstation soak does not attest a
  server arm).

The attestation is produced by the operator from `soak-report.sh` output after a triaged
≥14-day shadow soak; it is **never** generated by agentd itself. Absent/unparseable/stale/
non-zero-FP ⇒ refuse. Unit tests cover each failing field and the one passing shape.

**Fail-closed parsing (M5).** The validator decodes into a struct whose required fields are
**pointers**, so a **missing** `schema` / `duration_days` / `distinct_would_quarantine` /
`unexplained_fp` / `generated_at` / `host_class` is a nil pointer ⇒ **refuse** (it never
silently decodes to a passing `0`/`""`). After decoding the single object it requires
`dec.More()==false`, so **trailing data or a decoy second JSON object** after a valid one is
**refused** (a `json.Decoder` would otherwise read only the first and ignore the rest).
`generated_at` must be RFC3339 and **not in the future** beyond a small clock skew (a future
timestamp would otherwise pass the staleness check by making `age` negative). Every failure
yields a non-empty, precise refusal reason.

**Wired into the runtime arm gate (M6).** `checkArmingGate` (main.go) now passes the
configured attestation path (`AGENT_AUTORESPONSE_SOAK_ATTESTED`), the host class
(`AGENT_AUTORESPONSE_HOST_CLASS`), and the staleness bound
(`AGENT_AUTORESPONSE_ATTESTATION_MAX_AGE`) into `ArmingInputs`, so the **real §3 validator
runs at startup** instead of degrading to a mere file-exists check. The legacy existence-only
gate is kept **only** as a fallback when no path is configured. This does **not** un-gate: a
malformed/short/stale attestation makes the soak refusal reason appear in the arm-gate
output, and the two deferred rails still refuse canary/armed regardless.

## 4. Grace/veto (CANCEL) queue

`GraceQueue` (`grace_queue.go`) holds, per pending action keyed on the stable
`action|target|dst` tuple: the `Request`, its planned inverse `Request`, and a timer.

- `Enqueue(req, inverse, window)` starts a timer; returns a handle. The inverse is enqueued
  as a **template** — its Action + origin are set, but its **Target (the quarantine
  destination) is intentionally empty**: that destination is unknown until the forward runs.
- `Cancel(key)` (operator veto, via the future console push channel) stops the timer; if
  the action was already applied, it builds the inverse's Target from the forward Result's
  **structured `QuarantineDst`** (M1 — a machine-readable Result field, never parsed out of
  free-text Detail), invokes the inverse through the Responder, and audits the veto. It
  returns whether a veto **landed** — **true only after a successful reversal**; a failed or
  un-addressable inverse returns false.
- **Forward↔inverse synchronisation (M1+M2).** Each pending item runs a state machine
  `pending → applying → applied`. `fire()` runs the forward, records its Result, then marks
  the item applied; a `Cancel` that races an in-flight forward (state `applying`) **blocks
  until the forward completes** and only then builds/runs the inverse from the forward's real
  Result — so the inverse can **never precede or run concurrent with the forward** (the prior
  bug, reproduced 200/200, where an inverse with no Target — and unsynchronised with the
  forward — could run first and could never reverse a quarantine).
- On expiry with no veto, the action is allowed to stand (it was already executed; grace is
  a *post-action* undo window for reversible actions, a *pre-action* hold for the rest per
  §4.6 #14 — quarantine gets the hold).
- Fail-closed: a Cancel whose inverse fails (or whose forward reported no structured
  destination) audits LOUDLY and emits a CRITICAL finding; it never silently assumes
  reversibility.

## 5. Lockout watchdog + auto-rollback (§4.3)

`LockoutWatchdog` (`watchdog.go`) auto-undoes journaled actions **only on a positive
operator-lockout signal**, never on mere collector-unreachability:

- **Trigger:** the operator's live access is severed — `/run/agentd/response.sock`
  unreachable **and/or** the operator session's `oif` is down. Collector-unreachable alone
  does **not** trigger (a real intrusion / WAN flap routinely makes the collector
  unreachable; tearing down containment then is the wrong move and hands an attacker an
  uncontain primitive).
- **Debounced trigger (N4).** A single transient unreachability blip must not fire the
  rollback. `CheckAndRollback` requires **M consecutive lockout ticks spanning a minimum
  duration** (`WithDebounce(minTicks, minDuration, clock)`; default immediate for a
  single-shot caller) and **re-confirms the lockout after the journal walk** — if operator
  access recovered during the walk, the result carries a loud WARNING that the signal was
  transient. **Residual risk (honest):** the lockout signal is **attacker-forgeable** — an
  adversary who can sever `response.sock` or down the operator `oif` (e.g. kill sshd, flap
  the link) can *forge a sustained lockout* and drive the auto-uncontain. The debounce
  raises the cost (the lockout must be sustained, not a blip) but does **not** eliminate
  it; the conservative trigger set (operator-access-only, never collector) and the loud
  CRITICAL on every undo are the compensating controls. A future hardening is to require a
  *signed* operator-presence heartbeat rather than mere reachability.
- **Action:** walk the undo journal newest-first and invoke each inverse through the
  Responder. **Verify each undo succeeded** (the `nft` reverse shells out best-effort and
  can fail leaving a half-isolated host) and **alert loudly + emit CRITICAL on any undo
  failure** instead of assuming reversibility. Reverse actuators are **idempotent (N5):** a
  reverse whose end-state already holds (e.g. `nft delete table` on an already-absent table,
  or an unquarantine whose source is already gone and origin already restored) is treated
  as **success**, not a spurious CRITICAL.
- **Not coupled to the kill-switch.** Auto-undo and a kill-switch trip are deliberately
  independent; coupling them would hand an attacker a combined uncontain+disarm primitive.
- **Reverse rescue BYPASSES the kill-switch AND the rate limiter (M3+M4).** The watchdog
  runs its rescue inverses through `Responder.RespondRescue`, **not** `Respond`. Using the
  shared `Respond` would silently **defeat the rescue twice over**: the auto rate budget is
  exhausted by the preceding containment burst (so the un-contain would be rate-refused),
  and a kill-switch trip would refuse the un-contain too. §4.3/§5 deliberately **decouples
  auto-undo from both brakes — the operator must ALWAYS be un-lockable.** The decision: the
  **kill-switch stops FORWARD auto-actions, never the operator-rescue un-contain**; likewise
  the rate budget caps forward mass-action, never the rescue. The bypass is **scoped to the
  reverse actuators** (`unquarantine`/`de-isolate`/`restore-key`) — `RespondRescue`
  **refuses any forward action**, so the exempt path can never be turned into a way to run a
  kill/isolate/quarantine around the brakes. Forward actions keep flowing through `Respond`,
  where the kill-switch and rate limit still apply, and the reverse rescue still runs
  `Validate` + the full audit (only the two brakes are skipped).

## 6. Tests (safety-proving)

Existing invariants kept green **unchanged**: `TestBridgeHasNoExecutorField`,
`TestBridgeNeverExecutesEvenWithEverythingConstructed`,
`TestConsiderEligibleEmitsShadowWouldQuarantine`, the responder brakes tests.

New tests:
- `TestArmingStillRefusedInThisBuild` — canary/armed still refused even with a perfect soak
  attestation, because `deferredUnmet` retains the console-push + authenticated-export
  rails. (The runtime-inert guarantee.)
- `TestSoakAttestation*` — each failing field (short duration, non-zero FP, stale,
  unparseable, host-class mismatch) refuses; the one valid shape passes the soak gate.
- `TestGraceVetoExpiryAllows` / `TestGraceVetoCancelInvokesInverse` /
  `TestGraceVetoInverseFailureAlerts`.
- `TestWatchdogTriggersOnlyOnOperatorLockout` (collector-unreachable-alone does NOT
  trigger) / `TestWatchdogAutoRollbackWalksJournal` / `TestWatchdogUndoFailureAlerts` /
  `TestWatchdogNotCoupledToKillSwitch`.
- `TestAutoActuatorShadowNeverExecutes` (off/dry-run/shadow never call Execute) and
  `TestAutoActuatorCanaryRequiresAllGates` (the only execute path needs mode + attestation
  + grace-expiry; any missing gate ⇒ no Execute).
