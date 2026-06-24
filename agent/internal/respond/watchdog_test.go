package respond

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// watchdog_test.go exercises the §5 lockout watchdog with INJECTED reachability
// probes (deterministic, no real sockets/interfaces) and an injected, recording
// FakeExecutor through a LIVE responder.

// watchdogResponder builds a LIVE responder over a FakeExecutor (or a shaped one).
func watchdogResponder(fake *FakeExecutor) (*Responder, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	r := NewResponder(fake, NewAuditLog(buf), false /* live */, graceGuards(), fixedClock())
	return r, buf
}

// sampleUndoRecords returns two journaled actions (oldest-first): an isolate then
// a quarantine, each with a structured inverse. The watchdog walks them
// newest-first.
func sampleUndoRecords() []UndoRecord {
	return []UndoRecord{
		{
			Request: Request{Action: ActionIsolate, Target: "host"},
			Inverse: Request{Action: ActionDeIsolate, Target: "host"},
		},
		{
			Request: Request{Action: ActionQuarantine, Target: "/tmp/.x/payload"},
			Inverse: Request{Action: ActionUnquarantine, Target: "/var/lib/agentd/quarantine/1-payload", Args: map[string]string{"origin": "/tmp/.x/payload"}},
		},
	}
}

// up/down are probe helpers.
func up() bool   { return true }
func down() bool { return false }

// TestWatchdogTriggersOnlyOnOperatorLockout: the watchdog rolls back ONLY on a
// positive operator-lockout signal; collector-unreachable ALONE does NOT trigger.
func TestWatchdogTriggersOnlyOnOperatorLockout(t *testing.T) {
	recs := sampleUndoRecords()

	t.Run("collector-unreachable-alone does NOT trigger", func(t *testing.T) {
		fake := &FakeExecutor{}
		r, _ := watchdogResponder(fake)
		w := NewLockoutWatchdog(r, LockoutProbes{
			ResponseSockReachable: up,   // operator control channel UP
			OperatorOifUp:         up,   // operator oif UP
			CollectorReachable:    down, // collector DOWN — but that is NOT a lockout
		})
		res := w.CheckAndRollback(recs)
		if res.Triggered {
			t.Fatal("collector-unreachable ALONE must NOT trigger auto-rollback (uncontain hazard)")
		}
		if fake.CallCount() != 0 {
			t.Errorf("no inverses should run when not triggered, got %d", fake.CallCount())
		}
	})

	t.Run("response.sock unreachable DOES trigger", func(t *testing.T) {
		fake := &FakeExecutor{}
		r, _ := watchdogResponder(fake)
		w := NewLockoutWatchdog(r, LockoutProbes{
			ResponseSockReachable: down, // operator control channel SEVERED
			OperatorOifUp:         up,
			CollectorReachable:    up,
		})
		if !w.CheckAndRollback(recs).Triggered {
			t.Fatal("response.sock unreachable is a positive lockout signal — must trigger")
		}
	})

	t.Run("operator oif down DOES trigger", func(t *testing.T) {
		fake := &FakeExecutor{}
		r, _ := watchdogResponder(fake)
		w := NewLockoutWatchdog(r, LockoutProbes{
			ResponseSockReachable: up,
			OperatorOifUp:         down, // operator session interface DOWN
			CollectorReachable:    up,
		})
		if !w.CheckAndRollback(recs).Triggered {
			t.Fatal("operator oif down is a positive lockout signal — must trigger")
		}
	})

	t.Run("all up does NOT trigger", func(t *testing.T) {
		fake := &FakeExecutor{}
		r, _ := watchdogResponder(fake)
		w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: up, OperatorOifUp: up, CollectorReachable: up})
		if w.CheckAndRollback(recs).Triggered {
			t.Fatal("no lockout signal must not trigger")
		}
	})

	t.Run("nil probes fail closed against a false trigger", func(t *testing.T) {
		fake := &FakeExecutor{}
		r, _ := watchdogResponder(fake)
		// No probes set at all — must NOT be read as a lockout (would auto-uncontain).
		w := NewLockoutWatchdog(r, LockoutProbes{})
		if w.CheckAndRollback(recs).Triggered {
			t.Fatal("absent probes must NOT trigger an auto-rollback (fail-closed against false trigger)")
		}
	})
}

// TestWatchdogAutoRollbackWalksJournal: on a lockout, the watchdog walks the
// journal NEWEST-FIRST and runs each inverse through the Responder.
func TestWatchdogAutoRollbackWalksJournal(t *testing.T) {
	fake := &FakeExecutor{}
	r, _ := watchdogResponder(fake)
	w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: down, OperatorOifUp: up})

	res := w.CheckAndRollback(sampleUndoRecords())
	if !res.Triggered || res.UndosRun != 2 || res.UndoFailed != 0 {
		t.Fatalf("expected 2 clean undos, got %+v", res)
	}
	if fake.CallCount() != 2 {
		t.Fatalf("both inverses should run, got %d calls", fake.CallCount())
	}
	// NEWEST-FIRST: the quarantine (last journaled) is lifted before the isolate.
	if fake.Calls[0].Action != ActionUnquarantine || fake.Calls[1].Action != ActionDeIsolate {
		t.Errorf("journal must be walked newest-first; got %q then %q", fake.Calls[0].Action, fake.Calls[1].Action)
	}
	if len(w.CriticalFindings()) != 0 {
		t.Errorf("a clean rollback emits no CRITICAL: %v", w.CriticalFindings())
	}
}

// TestWatchdogUndoFailureAlerts: any undo that does not verify (executor error)
// emits a CRITICAL finding and a LOUD audit line — never assume reversibility.
func TestWatchdogUndoFailureAlerts(t *testing.T) {
	fake := &FakeExecutor{Err: errors.New("nft delete failed")} // every inverse fails
	buf := &bytes.Buffer{}
	r := NewResponder(fake, NewAuditLog(buf), false /* live */, graceGuards(), fixedClock())
	w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: down, OperatorOifUp: up})

	res := w.CheckAndRollback(sampleUndoRecords())
	if !res.Triggered || res.UndoFailed != 2 {
		t.Fatalf("both failing undos must be counted as failures, got %+v", res)
	}
	crit := w.CriticalFindings()
	if len(crit) != 2 {
		t.Fatalf("each undo failure must emit a CRITICAL finding, got %d", len(crit))
	}
	for _, c := range crit {
		if c.Severity != report.SeverityCritical {
			t.Errorf("undo-failure alert must be CRITICAL, got %v", c.Severity)
		}
	}
	if !bytes.Contains(buf.Bytes(), []byte("LOCKOUT AUTO-ROLLBACK FAILED")) {
		t.Errorf("an undo failure must write a LOUD audit line; audit=%s", buf.String())
	}
}

// TestWatchdogDryRunResponderFailsSafe (N7) pins the fail-safe path against a
// DRY-RUN Responder — the ONLY mode a runtime agentd can actually construct in this
// build. A dry-run inverse does NOT actually reverse anything during an active
// lockout, so the watchdog must count it as an undo FAILURE (UndoFailed>0) and emit
// a CRITICAL — never a silent "looks OK because Result.OK". This is the real
// runtime shape: if the watchdog were ever (wrongly) driven from a dry-run runtime,
// it must fail loud, not pretend the host was un-contained.
func TestWatchdogDryRunResponderFailsSafe(t *testing.T) {
	fake := &FakeExecutor{}
	buf := &bytes.Buffer{}
	// DRY-RUN responder (dryRun=true) — the runtime-constructible mode.
	r := NewResponder(fake, NewAuditLog(buf), true /* DRY-RUN */, graceGuards(), fixedClock())
	w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: down})

	res := w.CheckAndRollback(sampleUndoRecords())
	if !res.Triggered {
		t.Fatal("the watchdog should trigger on the lockout signal")
	}
	if res.UndoFailed == 0 {
		t.Fatalf("a DRY-RUN inverse did not actually reverse anything — it must count as an undo FAILURE, got %+v", res)
	}
	if res.UndoFailed != 2 {
		t.Errorf("both dry-run inverses must be failures, got %+v", res)
	}
	if len(w.CriticalFindings()) != 2 {
		t.Errorf("each dry-run (non-reversing) inverse must emit a CRITICAL, got %d", len(w.CriticalFindings()))
	}
	if !bytes.Contains(buf.Bytes(), []byte("LOCKOUT AUTO-ROLLBACK FAILED")) {
		t.Errorf("a dry-run inverse must write a LOUD audit line; audit=%s", buf.String())
	}
	// The executor was NOT reached (dry-run returns the plan without Execute).
	if fake.CallCount() != 0 {
		t.Errorf("a dry-run responder must not reach the executor, got %d", fake.CallCount())
	}
}

// TestGraceDryRunResponderFailsSafe (N7, grace twin): a veto whose inverse runs
// through a DRY-RUN responder did NOT actually reverse the (live-applied) action —
// the grace queue must treat it as a failed reversal: CRITICAL + landed=false.
func TestGraceDryRunResponderFailsSafe(t *testing.T) {
	fake := &FakeExecutor{}
	buf := &bytes.Buffer{}
	// DRY-RUN responder: the forward "applies" as a dry-run and the inverse is dry-run
	// too. A dry-run inverse cannot reverse a real action, so the veto fails safe.
	r := NewResponder(fake, NewAuditLog(buf), true /* DRY-RUN */, graceGuards(), fixedClock())
	clk := &fakeGraceClock{}
	q := NewGraceQueue(r, time.Minute, clk)

	item := realInverseGraceItem(t)
	q.Enqueue(item)
	clk.fireAll() // forward "applied" (dry-run)
	if landed := q.Cancel(item.key); landed {
		t.Fatal("a dry-run inverse cannot reverse a real action — the veto must report landed=false")
	}
	if len(q.CriticalFindings()) != 1 {
		t.Fatalf("a non-reversing (dry-run) inverse must emit CRITICAL, got %d", len(q.CriticalFindings()))
	}
}

// An irreversible journaled action (no inverse) is a VERIFY failure: it cannot
// restore the operator's access, so it alerts CRITICAL.
func TestWatchdogIrreversibleActionAlerts(t *testing.T) {
	fake := &FakeExecutor{}
	r, _ := watchdogResponder(fake)
	w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: down})

	recs := []UndoRecord{{Request: Request{Action: ActionKill, Target: "1337"}, Inverse: Request{}}}
	res := w.CheckAndRollback(recs)
	if res.UndoFailed != 1 {
		t.Fatalf("an irreversible action must count as an undo failure, got %+v", res)
	}
	if len(w.CriticalFindings()) != 1 {
		t.Errorf("an irreversible action must emit CRITICAL, got %d", len(w.CriticalFindings()))
	}
}

// TestWatchdogNotCoupledToKillSwitch: the watchdog holds no kill-switch reference
// and never trips it — auto-undo and a kill-switch trip are independent (avoiding
// a combined uncontain+disarm primitive). We assert STRUCTURALLY (no kill-switch
// field) and BEHAVIOURALLY (a rollback leaves a Responder kill-switch untouched).
func TestWatchdogNotCoupledToKillSwitch(t *testing.T) {
	// Structural: the watchdog type holds no kill-switch path/probe.
	wt := reflect.TypeOf(LockoutWatchdog{})
	for i := 0; i < wt.NumField(); i++ {
		name := strings.ToLower(wt.Field(i).Name)
		if strings.Contains(name, "kill") || strings.Contains(name, "switch") {
			t.Fatalf("LockoutWatchdog must not reference the kill-switch; found field %q", wt.Field(i).Name)
		}
	}

	// Behavioural: a rollback through a Responder armed with a kill-switch path does
	// NOT create/touch that kill-switch file; the path is unchanged after the walk.
	fake := &FakeExecutor{}
	buf := &bytes.Buffer{}
	r := NewResponder(fake, NewAuditLog(buf), false, graceGuards(), fixedClock()).
		WithKillSwitch("/run/agentd/response.disabled", func(string) bool { return false })
	w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: down})

	res := w.CheckAndRollback(sampleUndoRecords())
	if !res.Triggered {
		t.Fatal("watchdog should trigger on lockout")
	}
	if r.KillSwitchPath != "/run/agentd/response.disabled" {
		t.Errorf("watchdog must not alter the kill-switch path, got %q", r.KillSwitchPath)
	}
	if fake.CallCount() != 2 {
		t.Errorf("inverses should run (the watchdog did not trip the kill-switch), got %d", fake.CallCount())
	}
}

// TestWatchdogRescueBypassesKillSwitch (M4): with the kill-switch PRESENT (the
// review-flagged absent-only probe replaced by a present one), the rescue inverses
// STILL run live — RespondRescue bypasses the kill-switch so the operator is always
// un-lockable. This is the real path: a kill-switch trip must NOT defeat the rescue.
func TestWatchdogRescueBypassesKillSwitch(t *testing.T) {
	fake := &FakeExecutor{}
	buf := &bytes.Buffer{}
	r := NewResponder(fake, NewAuditLog(buf), false, graceGuards(), fixedClock()).
		WithKillSwitch("/run/agentd/response.disabled", func(string) bool { return true /* PRESENT */ })
	w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: down})

	res := w.CheckAndRollback(sampleUndoRecords())
	if !res.Triggered || res.UndoFailed != 0 || res.UndosRun != 2 {
		t.Fatalf("the rescue must run LIVE despite a tripped kill-switch, got %+v", res)
	}
	if fake.CallCount() != 2 {
		t.Fatalf("both rescue inverses must reach the executor despite the kill-switch, got %d", fake.CallCount())
	}
	if len(w.CriticalFindings()) != 0 {
		t.Errorf("a live rescue must not emit CRITICAL: %v", w.CriticalFindings())
	}

	// CONTRAST: a FORWARD action through the SAME (kill-switch-present) responder via
	// the normal Respond path is STILL refused — only the reverse rescue is exempt.
	fwd := r.Respond(Request{Action: ActionQuarantine, Target: "/tmp/.x/payload"})
	if fwd.OK {
		t.Error("a FORWARD action must STILL be refused by the kill-switch (only reverse rescue bypasses)")
	}
	if !strings.Contains(fwd.Detail, "kill-switch") {
		t.Errorf("the forward refusal should name the kill-switch, got %q", fwd.Detail)
	}
}

// TestWatchdogRescueBypassesRateLimit (M3): when the rate budget is EXHAUSTED by a
// preceding forward containment burst, the rescue inverses STILL run live —
// RespondRescue does not consume or check the rate limiter. The shared Respond
// would silently rate-refuse the un-contain (the bug); the rescue path fixes it.
func TestWatchdogRescueBypassesRateLimit(t *testing.T) {
	fake := &FakeExecutor{}
	buf := &bytes.Buffer{}
	// A rate budget of 1 per long window. Exhaust it with one forward, then prove the
	// reverse rescue is unaffected.
	r := NewResponder(fake, NewAuditLog(buf), false, graceGuards(), fixedClock()).
		WithRateLimit(1, time.Hour)

	// Forward #1 consumes the only budget slot (a live quarantine).
	dr := false
	if got := r.Respond(Request{Action: ActionQuarantineFD, Target: "1337", DryRun: &dr,
		Args: map[string]string{"starttime": "5000", "staging_dirs": "/tmp/"}}); !got.OK {
		t.Fatalf("the first forward should consume the budget and succeed: %+v", got)
	}
	// Forward #2 is now rate-refused (budget exhausted).
	if got := r.Respond(Request{Action: ActionQuarantineFD, Target: "1338", DryRun: &dr,
		Args: map[string]string{"starttime": "5000", "staging_dirs": "/tmp/"}}); got.OK {
		t.Fatalf("the second forward should be rate-refused, got %+v", got)
	}
	callsBefore := fake.CallCount()

	// The rescue rolls back despite the exhausted budget.
	w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: down})
	res := w.CheckAndRollback(sampleUndoRecords())
	if !res.Triggered || res.UndoFailed != 0 || res.UndosRun != 2 {
		t.Fatalf("the rescue must run LIVE despite an exhausted rate budget, got %+v", res)
	}
	if fake.CallCount() != callsBefore+2 {
		t.Fatalf("both rescue inverses must reach the executor despite the exhausted budget, got %d new", fake.CallCount()-callsBefore)
	}
}

// TestRespondRescueRefusesForwardAction: the rescue entrypoint is SCOPED to reverse
// actions — a forward/containment action through RespondRescue is REFUSED, so the
// kill/rate bypass can never be used to run a forward around the brakes.
func TestRespondRescueRefusesForwardAction(t *testing.T) {
	spy := &spyExecutor{}
	r := NewResponder(spy, NewAuditLog(&bytes.Buffer{}), false, graceGuards(), fixedClock())
	for _, a := range []string{ActionKill, ActionIsolate, ActionQuarantine, ActionQuarantineFD, ActionRevokeKey, ActionBlockHash} {
		res := r.RespondRescue(Request{Action: a, Target: "1337"})
		if res.OK {
			t.Errorf("RespondRescue must REFUSE forward action %q (rescue is reverse-only)", a)
		}
	}
	if got := atomic.LoadInt64(&spy.calls); got != 0 {
		t.Fatalf("a refused forward rescue must never reach the executor, got %d", got)
	}
}

// TestWatchdogDebounceRequiresSustainedLockout (N4): a single transient lockout
// tick must NOT fire the rollback; only minTicks consecutive ticks spanning
// minDuration do. A recovery between ticks RESETS the streak so a blip never fires.
func TestWatchdogDebounceRequiresSustainedLockout(t *testing.T) {
	recs := sampleUndoRecords()
	// A controllable clock + a controllable lockout signal.
	var now time.Time
	clock := func() time.Time { return now }
	sockReachable := true
	probe := func() bool { return sockReachable }

	fake := &FakeExecutor{}
	r, _ := watchdogResponder(fake)
	// Require 3 consecutive lockout ticks spanning >= 30s.
	w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: probe}).
		WithDebounce(3, 30*time.Second, clock)

	// Tick 1: lockout begins.
	now = time.Unix(0, 0)
	sockReachable = false
	if res := w.CheckAndRollback(recs); res.Triggered {
		t.Fatal("a single lockout tick must NOT fire the rollback (debounce)")
	}
	// Tick 2: still locked out, but only 10s elapsed and only 2 ticks.
	now = now.Add(10 * time.Second)
	if res := w.CheckAndRollback(recs); res.Triggered {
		t.Fatal("two ticks / 10s must NOT yet satisfy the debounce")
	}
	// A RECOVERY blip resets the streak.
	now = now.Add(10 * time.Second)
	sockReachable = true
	if res := w.CheckAndRollback(recs); res.Triggered {
		t.Fatal("a recovery tick must reset the streak, not fire")
	}
	if fake.CallCount() != 0 {
		t.Fatalf("nothing should have rolled back during the debounce, got %d calls", fake.CallCount())
	}

	// Now a SUSTAINED lockout: 3 consecutive ticks spanning > 30s.
	sockReachable = false
	now = now.Add(10 * time.Second) // tick A (streak=1, firstSeen here)
	w.CheckAndRollback(recs)
	now = now.Add(20 * time.Second) // tick B (streak=2)
	w.CheckAndRollback(recs)
	now = now.Add(20 * time.Second) // tick C (streak=3, span 40s >= 30s) → FIRE
	res := w.CheckAndRollback(recs)
	if !res.Triggered {
		t.Fatal("3 consecutive lockout ticks spanning >30s MUST fire the rollback")
	}
	if fake.CallCount() != 2 {
		t.Fatalf("the sustained lockout should roll back both inverses, got %d", fake.CallCount())
	}
}

// TestWatchdogReconfirmsAfterWalk (N4): if operator access RECOVERS during the
// rollback walk, the re-confirm surfaces a WARNING in the Detail (the signal was
// transient) — the honest post-walk record.
func TestWatchdogReconfirmsAfterWalk(t *testing.T) {
	// The sock probe returns DOWN on the trigger check but UP on the post-walk
	// re-confirm: a tiny state machine flips it after the first read.
	reads := 0
	sock := func() bool {
		reads++
		return reads > 1 // first read (trigger) = down; later reads (re-confirm) = up
	}
	fake := &FakeExecutor{}
	r, _ := watchdogResponder(fake)
	w := NewLockoutWatchdog(r, LockoutProbes{ResponseSockReachable: sock})

	res := w.CheckAndRollback(sampleUndoRecords())
	if !res.Triggered {
		t.Fatal("the first (down) read must trigger the rollback")
	}
	if !strings.Contains(res.Detail, "RECOVERED") {
		t.Errorf("a post-walk recovery must be surfaced in Detail, got %q", res.Detail)
	}
}
