package respond

import (
	"fmt"
	"sync"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// watchdog.go is the §4.3/§5 lockout watchdog + auto-rollback. After a live auto
// action, if the OPERATOR's own access is severed, it auto-undoes the journaled
// actions so a containment action can never lock the operator out of their own
// host. RUNTIME-INERT in this build: no runtime caller drives it (canary/armed are
// refused at startup); it is exercised only by unit tests with injected probes.
//
// ═══ THREE NON-NEGOTIABLE PROPERTIES (§5) ═══
//  1. Triggers ONLY on a POSITIVE operator-lockout signal — response.sock
//     unreachable AND/OR the operator session's oif down. Collector-unreachable
//     ALONE does NOT trigger: a real intrusion / WAN flap routinely makes the
//     collector unreachable, and tearing down containment then hands an attacker an
//     uncontain primitive. (N4: the trigger is DEBOUNCED — see CheckAndRollback /
//     RollbackDecider — so a single transient blip cannot fire the rollback.)
//  2. VERIFIES each undo and alerts LOUDLY + emits CRITICAL on ANY undo failure —
//     the nft/fs reverse shells out best-effort and can leave a half-isolated host;
//     it never assumes reversibility.
//  3. NOT coupled to the kill-switch — auto-undo and a kill-switch trip are
//     deliberately independent; coupling them would hand an attacker a combined
//     uncontain+disarm primitive.
//
// ═══ RESCUE BYPASSES THE KILL-SWITCH AND RATE LIMITER (M3+M4) ═══
// The rescue inverses run through Responder.RespondRescue, NOT Respond. Respond
// would silently DEFEAT the rescue twice over: the rate budget is exhausted by the
// preceding containment burst (so the un-contain would be rate-refused), and a
// kill-switch trip would refuse the un-contain too. §4.3/§5 deliberately decouples
// auto-undo from BOTH brakes — the operator must ALWAYS be un-lockable. The bypass
// is SCOPED to the reverse actuators (Unquarantine/DeIsolate/RestoreKey); RespondRescue
// REFUSES any forward action, so the exempt path can never run a containment action
// around the brakes. The kill-switch and rate limit continue to stop FORWARD
// auto-actions; they never stop the operator-rescue un-contain.

// LockoutProbes are the injectable reachability checks (§5). They are the ONLY
// signal the watchdog reads to decide whether to roll back, so tests drive the
// trigger deterministically without real sockets/interfaces. Each returns true
// when the resource IS reachable/up.
type LockoutProbes struct {
	// ResponseSockReachable reports whether /run/agentd/response.sock is reachable
	// (the operator's live control channel). false ⇒ part of a lockout signal.
	ResponseSockReachable func() bool
	// OperatorOifUp reports whether the operator session's outbound interface is up
	// (e.g. the SSH/Tailscale oif). false ⇒ part of a lockout signal.
	OperatorOifUp func() bool
	// CollectorReachable reports whether the collector is reachable. It is read for
	// CONTEXT/audit ONLY and DELIBERATELY does NOT gate the trigger — collector loss
	// alone must never auto-uncontain (property #1). nil ⇒ unknown (treated as
	// reachable for audit purposes).
	CollectorReachable func() bool
}

// LockoutWatchdog auto-rolls-back journaled auto actions on a positive operator-
// lockout signal. It runs the inverses through the SAME Responder, verifies each,
// and emits CRITICAL findings on any failure. It holds no kill-switch reference
// (property #3).
//
// N4 DEBOUNCE: the trigger requires minTicks CONSECUTIVE lockout ticks spanning at
// least minDuration before it fires, and RE-CONFIRMS the lockout AFTER the journal
// walk. A single transient blip (one tick of unreachability that recovers next
// tick) therefore cannot fire the rollback. The DEFAULT (minTicks=1, minDuration=0)
// is immediate — backward-compatible with a single-shot caller — and a caller arms
// the debounce via WithDebounce. RESIDUAL RISK (documented, §5): the lockout
// signal is attacker-FORGEABLE — an adversary who can sever response.sock / down
// the operator oif (e.g. by killing the sshd or flapping the link) can FORGE a
// sustained lockout and drive the auto-uncontain. The debounce raises the cost (it
// must be sustained, not a blip) but does not eliminate it; the conservative
// trigger set (operator-access-only, never collector) and the loud CRITICAL on
// every undo are the compensating controls.
type LockoutWatchdog struct {
	resp   *Responder
	probes LockoutProbes

	// Debounce (N4): minTicks consecutive lockout observations spanning >= minDuration
	// are required before the rollback fires. now is the injected clock for the
	// duration check (nil ⇒ time.Now).
	minTicks    int
	minDuration time.Duration
	now         func() time.Time

	mu        sync.Mutex
	critical  []report.Finding // CRITICAL findings (undo-failure alerts)
	streak    int              // consecutive lockout ticks observed so far
	firstSeen time.Time        // timestamp of the first tick in the current streak
}

// NewLockoutWatchdog builds the watchdog over the Responder and the injected
// reachability probes. The debounce defaults to immediate (1 tick, 0 duration);
// call WithDebounce to require a sustained lockout (N4).
func NewLockoutWatchdog(resp *Responder, probes LockoutProbes) *LockoutWatchdog {
	return &LockoutWatchdog{resp: resp, probes: probes, minTicks: 1}
}

// WithDebounce arms the N4 debounce: the rollback fires only after minTicks
// CONSECUTIVE lockout ticks spanning at least minDuration. minTicks<1 is clamped to
// 1 (always at least one observation). now is the injected clock for the duration
// gate (nil ⇒ time.Now). Returns the watchdog for chaining.
func (w *LockoutWatchdog) WithDebounce(minTicks int, minDuration time.Duration, now func() time.Time) *LockoutWatchdog {
	if minTicks < 1 {
		minTicks = 1
	}
	w.minTicks = minTicks
	w.minDuration = minDuration
	w.now = now
	return w
}

// clock returns the watchdog's injected time or time.Now.
func (w *LockoutWatchdog) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

// observeLockout advances the debounce state machine for one tick and reports
// whether the rollback may fire NOW: a lockout observation extends the streak (and
// stamps firstSeen on the first one), a recovery RESETS it. The gate opens only
// once the streak reaches minTicks AND has spanned minDuration. A non-lockout tick
// always returns false (and resets the streak), so a single blip cannot fire.
func (w *LockoutWatchdog) observeLockout(lockedOut bool, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !lockedOut {
		w.streak = 0
		w.firstSeen = time.Time{}
		return false
	}
	if w.streak == 0 {
		w.firstSeen = now
	}
	w.streak++
	if w.streak < w.minTicks {
		return false
	}
	if now.Sub(w.firstSeen) < w.minDuration {
		return false
	}
	return true
}

// OperatorLockedOut evaluates property #1: a POSITIVE operator-lockout signal is
// response.sock unreachable AND/OR the operator oif down. Collector-unreachability
// is NOT part of this decision. Fail-closed against a FALSE trigger: a nil/unknown
// probe is treated as "reachable/up" (NOT locked out), so a missing probe can
// never by itself cause an auto-uncontain. The lockout is real only when a probe
// AFFIRMATIVELY reports the operator's access is severed.
func (w *LockoutWatchdog) OperatorLockedOut() bool {
	sockDown := w.probes.ResponseSockReachable != nil && !w.probes.ResponseSockReachable()
	oifDown := w.probes.OperatorOifUp != nil && !w.probes.OperatorOifUp()
	return sockDown || oifDown
}

// RollbackResult reports the outcome of a watchdog evaluation: whether it
// triggered, how many undos ran, and how many failed (each failure also emitted a
// CRITICAL finding).
type RollbackResult struct {
	Triggered  bool
	UndosRun   int
	UndoFailed int
	// Detail explains a no-trigger (e.g. "no operator-lockout signal").
	Detail string
}

// CheckAndRollback is the watchdog tick: if (and ONLY if) the operator is locked
// out FOR A DEBOUNCED, SUSTAINED interval (N4), walk the undo journal NEWEST-FIRST
// and run each inverse through the rescue path, verifying each. It does NOT trigger
// on collector-unreachability alone, nor on a single transient lockout blip.
// records are the journaled UndoRecords in chronological (oldest-first) order; the
// walk reverses them so the most recent containment is lifted first.
func (w *LockoutWatchdog) CheckAndRollback(records []UndoRecord) RollbackResult {
	now := w.clock()
	lockedOut := w.OperatorLockedOut()
	// N4 debounce: advance the streak state machine; fire only on a sustained lockout.
	if !w.observeLockout(lockedOut, now) {
		collector := "unknown"
		if w.probes.CollectorReachable != nil {
			if w.probes.CollectorReachable() {
				collector = "reachable"
			} else {
				collector = "UNREACHABLE (not a trigger by itself)"
			}
		}
		if !lockedOut {
			return RollbackResult{Triggered: false, Detail: "no operator-lockout signal; collector=" + collector}
		}
		// Locked out, but the debounce has not yet been satisfied (not enough
		// consecutive ticks / not enough elapsed time) — do NOT roll back on a blip.
		return RollbackResult{Triggered: false, Detail: "operator-lockout signal present but debounce not yet satisfied (awaiting a sustained lockout); collector=" + collector}
	}

	res := RollbackResult{Triggered: true}
	// Walk NEWEST-FIRST: lift the most recent containment first.
	for i := len(records) - 1; i >= 0; i-- {
		rec := records[i]
		inv := rec.Inverse
		if inv.Action == "" {
			// An irreversible forward (kill) has no inverse — that is a VERIFY
			// failure: we cannot restore the operator's access for this action.
			res.UndoFailed++
			w.alertUndoFailure(rec, "journaled action is irreversible (no inverse)", Result{})
			continue
		}
		res.UndosRun++
		// M3+M4: run the rescue inverse through the kill/rate-EXEMPT RespondRescue
		// path. The shared Respond would silently DEFEAT the rescue — the rate budget
		// is exhausted by the preceding containment burst, and a kill-switch trip would
		// block the un-contain — but §4.3/§5 decouples auto-undo from BOTH (the operator
		// must always be un-lockable). RespondRescue bypasses the kill-switch and the
		// rate limiter, scoped to reverse actions only (it refuses any forward action),
		// while still running Validate + the full audit.
		out := w.resp.RespondRescue(inv)
		// VERIFY the undo succeeded. The Responder's Result.OK is the verification:
		// a dry-run (OK but DryRun) did NOT actually reverse anything during an active
		// lockout, so it is also a failure (the watchdog must run live inverses).
		if !out.OK || out.DryRun {
			res.UndoFailed++
			w.alertUndoFailure(rec, "inverse Request did not reverse the action", out)
		}
	}

	// N4: RE-CONFIRM the lockout AFTER the walk. If operator access has RECOVERED by
	// the time the rollback completed, the signal was transient and we just
	// un-contained on a recovered host — surface that in the Detail so the audit
	// trail shows the post-walk state. (We do NOT re-contain: the inverses already
	// ran; the honest record is what matters, plus the streak reset below stops a
	// recovered signal from re-triggering on the next tick.)
	if !w.OperatorLockedOut() {
		res.Detail = "WARNING: operator access RECOVERED during/after the rollback walk — the lockout signal was transient; review whether the auto-uncontain was warranted"
		w.mu.Lock()
		w.streak = 0
		w.firstSeen = time.Time{}
		w.mu.Unlock()
	}
	return res
}

// alertUndoFailure records a LOUD audit line and emits a CRITICAL finding for an
// undo the watchdog could not verify. A half-rolled-back host is a containment
// hazard, so this is never silent (§5 property #2).
func (w *LockoutWatchdog) alertUndoFailure(rec UndoRecord, why string, res Result) {
	detail := fmt.Sprintf(
		"LOCKOUT AUTO-ROLLBACK FAILED for %s %q: %s; the host may remain half-contained — manual intervention required (inverse result: ok=%v dry_run=%v detail=%q)",
		rec.Request.Action, rec.Request.Target, why, res.OK, res.DryRun, res.Detail)
	if w.resp != nil && w.resp.Audit != nil {
		_ = w.resp.Audit.write(AuditRecord{
			Time:   w.resp.clock(),
			Stage:  "result",
			Action: "lockout-rollback-undo",
			Target: rec.Request.Target,
			OK:     false,
			Detail: detail,
		})
	}
	w.mu.Lock()
	w.critical = append(w.critical, report.Finding{
		Check:      "realtime.autoresponse.rollback_undo_failed",
		Severity:   report.SeverityCritical,
		Confidence: "high",
		Title:      "auto-response lockout rollback could not be verified",
		Detail:     detail,
		Related: []string{
			"forward_action=" + rec.Request.Action,
			"target=" + rec.Request.Target,
			"reason=" + why,
		},
	})
	w.mu.Unlock()
}

// CriticalFindings returns the CRITICAL undo-failure findings the watchdog has
// emitted. Test-facing read seam; a future console wire would drain these.
func (w *LockoutWatchdog) CriticalFindings() []report.Finding {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]report.Finding(nil), w.critical...)
}
