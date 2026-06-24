package respond

import (
	"fmt"
	"sync"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// grace_queue.go is the §4 grace/veto (CANCEL) window. Every would-be-live auto
// action is held here for AGENT_AUTORESPONSE_GRACE before it actually executes,
// giving an operator a window to VETO (CANCEL) it through the future console push
// channel. This is RUNTIME-INERT in this build: it has no runtime caller (canary/
// armed are refused at startup) and is exercised only by unit tests with an
// injected, deterministic timer.
//
// Per §4.6 #14 quarantine gets a PRE-action hold (the forward runs only on expiry);
// the cancel path also handles an already-applied action by running its inverse.
// Fail-closed: a Cancel whose inverse FAILS audits LOUDLY and emits a CRITICAL
// finding — it never silently assumes reversibility.
//
// ═══ FORWARD↔INVERSE SYNCHRONISATION (M1+M2) ═══
// The inverse is NOT runnable until the forward has actually applied, because the
// inverse's Target (the quarantine DESTINATION) is unknown until the forward
// Result reports it. Two coupled rules enforce this:
//   - fire() runs the forward, then populates the inverse Target from the forward
//     Result's STRUCTURED QuarantineDst (never free-text Detail) BEFORE the item is
//     marked runnable;
//   - a per-item state machine pending→applying→applied. A Cancel that races an
//     in-flight forward (state "applying") BLOCKS until the forward completes and
//     then builds/runs the inverse from the forward's REAL Result — so the inverse
//     can never precede or run concurrent with the forward.

// graceItem is one pending action in the grace window: the stable dedup key, the
// forward (destructive) Request to run on expiry, and the structured inverse
// TEMPLATE to run if an operator vetoes an already-applied action. The inverse's
// Target is left EMPTY here: it is the quarantine destination, which only the
// forward Result knows, and fire()/Cancel fill it from that Result (M1).
type graceItem struct {
	key     string
	forward Request
	inverse Request
}

// graceTimer is the injectable timer the GraceQueue arms per item. It abstracts
// time.AfterFunc so tests fire expiry deterministically (no real sleeps). Stop
// reports whether it stopped the timer before it fired (matching time.Timer.Stop).
type graceTimer interface {
	Stop() bool
}

// graceClock schedules a callback after d and returns a graceTimer to cancel it.
// The production clock wraps time.AfterFunc; a test clock records pending fires and
// triggers them on demand. It is the ONLY source of asynchrony in the queue.
type graceClock interface {
	AfterFunc(d time.Duration, f func()) graceTimer
}

// realGraceClock is the production scheduler (time.AfterFunc). Unused in this build
// (no runtime caller); present so the future wire needs no new type.
type realGraceClock struct{}

func (realGraceClock) AfterFunc(d time.Duration, f func()) graceTimer {
	return time.AfterFunc(d, f)
}

// graceState is the per-item lifecycle (M2). It is the SOLE arbiter of whether the
// inverse may run: the inverse is only ever built/run once the forward reaches
// statApplied with a recorded forward Result.
type graceState int

const (
	// statPending: the arming timer is set; the forward has NOT run. A Cancel here
	// is a PRE-action veto (drop it; nothing to reverse).
	statPending graceState = iota
	// statApplying: fire() is RUNNING the forward Request right now. A Cancel here
	// must BLOCK on the item's done channel until the forward finishes, then run the
	// inverse from the forward's real Result. The inverse never precedes the forward.
	statApplying
	// statApplied: the forward completed; its Result (incl. the structured
	// QuarantineDst) is recorded. A Cancel here is a POST-action veto: build the
	// inverse Target from the recorded Result and run it.
	statApplied
)

// pending tracks a held action: its item, its arming timer, its lifecycle state,
// the forward Result once applied, and a done channel closed when the forward
// transitions out of statApplying (so a racing Cancel can wait for it).
type pending struct {
	item   graceItem
	timer  graceTimer
	state  graceState
	fwdRes Result        // the forward Result once statApplied (carries QuarantineDst)
	done   chan struct{} // closed when the forward leaves statApplying
}

// GraceQueue holds pending auto actions for the grace/veto window. It runs the
// forward Request through the SAME Responder on expiry and the inverse on a veto.
// All state is mutex-guarded so an expiry callback and an operator Cancel race
// cleanly. emit collects CRITICAL findings for a Cancel whose inverse fails.
type GraceQueue struct {
	resp   *Responder
	window time.Duration
	clock  graceClock

	mu           sync.Mutex
	pendingByKey map[string]*pending
	critical     []report.Finding // CRITICAL findings emitted (inverse-failure alerts)
}

// NewGraceQueue builds a grace queue over the Responder, with the given veto
// window and an injectable clock. A nil clock uses the real time.AfterFunc
// scheduler (production); tests inject a deterministic fakeGraceClock.
func NewGraceQueue(resp *Responder, window time.Duration, clock graceClock) *GraceQueue {
	if clock == nil {
		clock = realGraceClock{}
	}
	return &GraceQueue{
		resp:         resp,
		window:       window,
		clock:        clock,
		pendingByKey: make(map[string]*pending),
	}
}

// Enqueue holds item for the grace window. It arms a timer; when the timer fires
// with no intervening veto, the forward Request runs through the Responder (an
// APPLY) and the item stays pending so a late veto can still run the inverse. A
// second Enqueue for an already-pending key is a no-op (the dedup already
// collapsed the storm upstream; this is belt-and-suspenders).
func (q *GraceQueue) Enqueue(item graceItem) {
	q.mu.Lock()
	if _, dup := q.pendingByKey[item.key]; dup {
		q.mu.Unlock()
		return
	}
	p := &pending{item: item, state: statPending, done: make(chan struct{})}
	q.pendingByKey[item.key] = p
	// Arm the timer LAST, holding the lock, so the fire callback cannot run before
	// the map is populated. AfterFunc runs f on its own goroutine, which then takes
	// q.mu — it blocks until Enqueue releases it.
	p.timer = q.clock.AfterFunc(q.window, func() { q.fire(item.key) })
	q.mu.Unlock()
}

// fire is the expiry callback: with no veto, APPLY the forward Request through the
// Responder, record the forward Result, then transition pending→applied so a
// post-expiry Cancel can run the inverse built from that Result. The state moves
// pending→applying around the (lock-released) Responder call so a racing Cancel
// blocks on done rather than running the inverse before the forward finishes
// (M2). A vetoed (already-removed) key is ignored.
func (q *GraceQueue) fire(key string) {
	q.mu.Lock()
	p, ok := q.pendingByKey[key]
	if !ok || p.state != statPending {
		q.mu.Unlock()
		return
	}
	p.state = statApplying
	fwd := p.item.forward
	done := p.done
	q.mu.Unlock()

	// Run the forward action through the Responder (kill-switch, rate-limit, audit,
	// guards all enforced there) WITHOUT the lock held, so a concurrent Cancel does
	// not block the whole queue — it blocks only on this item's done channel.
	res := q.resp.Respond(fwd)

	q.mu.Lock()
	// The item may have been removed by a Cancel that is now waiting on done; if so,
	// still record the Result (Cancel reads fwdRes after done closes) but do not
	// re-insert it.
	p.fwdRes = res
	p.state = statApplied
	close(done) // wake any Cancel blocked in statApplying; it reads fwdRes
	q.mu.Unlock()
}

// Cancel is the operator VETO (via the future console push channel). It stops the
// arming timer; if the forward action was already APPLIED, it runs the structured
// inverse — whose Target is filled from the forward Result's structured
// QuarantineDst — through the Responder and reports the outcome. If the forward is
// IN-FLIGHT (statApplying), Cancel BLOCKS until it completes, then runs the inverse
// from the real Result, so the inverse never precedes the forward (M2). Returns
// whether a veto LANDED — true ONLY after a successful reversal (or a no-op
// pre-action veto); a failed inverse audits loudly, emits a CRITICAL finding, and
// returns false (it never silently assumes reversibility).
func (q *GraceQueue) Cancel(key string) bool {
	q.mu.Lock()
	p, ok := q.pendingByKey[key]
	if !ok {
		q.mu.Unlock()
		return false // nothing pending under this key — no veto landed
	}

	switch p.state {
	case statPending:
		// PRE-action veto: stop the timer so the forward never runs. If Stop reports
		// the timer had already fired (lost the race), fall through to wait for the
		// in-flight/applied forward rather than dropping it.
		stopped := true
		if p.timer != nil {
			stopped = p.timer.Stop()
		}
		if stopped && p.state == statPending {
			delete(q.pendingByKey, key)
			q.mu.Unlock()
			return true // forward never ran — nothing to reverse
		}
		// Timer already fired: fire() is running or done; fall through to wait.
		fallthrough

	case statApplying:
		// The forward is RUNNING. Release the lock and BLOCK on done until fire()
		// records the Result and transitions to statApplied — the inverse must never
		// precede the forward. Then re-acquire and proceed as a post-apply veto.
		done := p.done
		q.mu.Unlock()
		<-done
		q.mu.Lock()
		// Re-read: the item is still mapped (fire never removes it). It is now applied.
	}

	// statApplied (reached directly, by fallthrough, or after blocking on done):
	// run the inverse built from the forward's REAL Result.
	res := p.fwdRes
	delete(q.pendingByKey, key)
	inverse := p.item.inverse
	q.mu.Unlock()

	return q.runInverse(key, inverse, res)
}

// runInverse builds the §4.6 inverse Request from the forward Result and runs it
// through the Responder. The inverse Target is filled from the forward Result's
// STRUCTURED QuarantineDst (M1) when the template left it empty — never parsed out
// of free-text Detail. It returns true ONLY when the reversal succeeded; a missing
// destination, an irreversible forward, or a failed inverse Respond audits loudly,
// emits a CRITICAL finding, and returns false.
func (q *GraceQueue) runInverse(key string, inverse Request, fwd Result) bool {
	if inverse.Action == "" {
		// An irreversible forward (e.g. kill) has no inverse — a failed reversal.
		q.alertInverseFailure(key, "forward action is irreversible (no inverse)", Result{})
		return false
	}
	// Fill the inverse Target from the forward's structured destination when the
	// template did not carry one (the quarantine case: the dst is only known after
	// the forward ran). If neither the template nor the forward supply a Target the
	// inverse cannot be addressed — treat as a failed reversal, never guess.
	if inverse.Target == "" {
		inverse.Target = fwd.QuarantineDst
	}
	if inverse.Target == "" {
		q.alertInverseFailure(key, "forward Result carried no structured quarantine destination — cannot address the inverse", fwd)
		return false
	}
	res := q.resp.Respond(inverse)
	if !res.OK || res.DryRun {
		// A dry-run inverse during a live veto did NOT actually reverse anything, so
		// it is also a failed reversal (fail-closed, mirrors the watchdog).
		q.alertInverseFailure(key, "inverse Request did not reverse the action", res)
		return false
	}
	return true
}

// alertInverseFailure records a LOUD audit line and emits a CRITICAL finding for a
// veto whose inverse could not reverse the applied action. The host may now be in a
// half-actioned state, so this is never silent.
func (q *GraceQueue) alertInverseFailure(key, why string, res Result) {
	detail := fmt.Sprintf(
		"GRACE VETO INVERSE FAILED for %q: %s; the auto-action may NOT be reversed — manual intervention required (inverse result: ok=%v detail=%q)",
		key, why, res.OK, res.Detail)
	if q.resp != nil && q.resp.Audit != nil {
		_ = q.resp.Audit.write(AuditRecord{
			Time:   q.resp.clock(),
			Stage:  "result",
			Action: "grace-veto-inverse",
			Target: key,
			OK:     false,
			Detail: detail,
		})
	}
	q.mu.Lock()
	q.critical = append(q.critical, report.Finding{
		Check:      "realtime.autoresponse.veto_inverse_failed",
		Severity:   report.SeverityCritical,
		Confidence: "high",
		Title:      "auto-response grace veto could not be reversed",
		Detail:     detail,
		Related:    []string{"grace_key=" + key, "reason=" + why},
	})
	q.mu.Unlock()
}

// CriticalFindings returns (and is the read seam for) the CRITICAL inverse-failure
// findings the queue has emitted. Tests assert these; a future console wire would
// drain them to the operator.
func (q *GraceQueue) CriticalFindings() []report.Finding {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]report.Finding(nil), q.critical...)
}

// Pending reports the number of items currently held (armed or applied-but-not-
// vetoed). Test-facing.
func (q *GraceQueue) Pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pendingByKey)
}
