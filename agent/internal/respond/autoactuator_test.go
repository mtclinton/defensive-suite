package respond

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// autoactuator_test.go proves the ONE decision→execution wire is safe:
//   - off/dry-run/shadow NEVER call the live Responder (zero Execute calls);
//   - the only execute path needs ALL of mode + per-action arm + grace expiry;
//   - the Bridge feeds Intents via ActionIntents WITHOUT itself executing.

// liveSpyResponder builds a LIVE responder over a spyExecutor (defined in
// bridge_inert_test.go) so any reached Execute is counted.
func liveSpyResponder() (*Responder, *spyExecutor) {
	spy := &spyExecutor{}
	r := NewResponder(spy, NewAuditLog(&bytes.Buffer{}), false /* live */, graceGuards(), func() time.Time { return testNow })
	return r, spy
}

// eligibleIntent is the Intent the Bridge derives for the all-gates-pass finding.
func eligibleIntent(t *testing.T) Intent {
	t.Helper()
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	intents := b.ActionIntents([]report.Finding{eligibleFinding()})
	if len(intents) != 1 {
		t.Fatalf("expected exactly 1 eligible intent, got %d", len(intents))
	}
	return intents[0]
}

// --- ActionIntents: a READ-ONLY accessor that does not execute ---

// The Bridge's ActionIntents returns the eligible would-action intents derived
// from the SAME decide() path as the shadow finding — without executing and
// without an actuator reference.
func TestBridgeActionIntentsAreReadOnly(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	intents := b.ActionIntents([]report.Finding{eligibleFinding()})
	if len(intents) != 1 {
		t.Fatalf("want 1 intent for the eligible finding, got %d", len(intents))
	}
	it := intents[0]
	if it.Action != actionWouldQuarantine {
		t.Errorf("intent action=%q want quarantine", it.Action)
	}
	if it.Target != "/tmp/.x/payload" {
		t.Errorf("intent target must be the resolved /proc exe, got %q", it.Target)
	}
	if it.Dst != "8.8.8.8:443" {
		t.Errorf("intent dst=%q want 8.8.8.8:443", it.Dst)
	}
	if !it.DryRunDefault {
		t.Error("intent DryRunDefault must be TRUE (§4.4: dry-run unless explicitly armed)")
	}
	if it.Inverse.Action != ActionUnquarantine || it.Inverse.arg("origin") != "/tmp/.x/payload" {
		t.Errorf("intent inverse must be a structured unquarantine, got %+v", it.Inverse)
	}
	// An alert-only / off finding yields no intent.
	if got := b.ActionIntents(nil); got != nil {
		t.Errorf("no findings ⇒ no intents, got %v", got)
	}
}

// Off mode yields no intents.
func TestBridgeActionIntentsOffEmpty(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.Mode = ModeOff
	b := newTestBridge(cfg, liveStagingProc())
	if got := b.ActionIntents([]report.Finding{eligibleFinding()}); got != nil {
		t.Errorf("ModeOff must yield no intents, got %v", got)
	}
}

// --- TestAutoActuatorShadowNeverExecutes ---

// off/dry-run/shadow modes NEVER reach the live Responder: the spy executor records
// ZERO Execute calls regardless of how eligible the intent is.
func TestAutoActuatorShadowNeverExecutes(t *testing.T) {
	it := eligibleIntent(t)
	for _, mode := range []Mode{ModeOff, ModeDryRun, ModeShadow} {
		r, spy := liveSpyResponder()
		// Even with EVERYTHING wired (live responder + grace queue + armed action),
		// a shadow-class mode must not execute.
		grace := NewGraceQueue(r, time.Minute, &fakeGraceClock{})
		aa := NewAutoActuator(r, grace, []string{actionWouldQuarantine})

		res := aa.ActOn(it, mode)
		if res.Executed {
			t.Errorf("mode %v must not execute", mode)
		}
		if got := atomic.LoadInt64(&spy.calls); got != 0 {
			t.Fatalf("mode %v: shadow-class mode reached the executor %d times (must be 0)", mode, got)
		}
		if grace.Pending() != 0 {
			t.Errorf("mode %v must not enqueue anything in a shadow-class mode, pending=%d", mode, grace.Pending())
		}
	}
}

// --- TestAutoActuatorCanaryRequiresAllGates ---

// The only execute path needs mode (canary/armed) AND the action explicitly armed
// AND grace expiry. Missing ANY one ⇒ no Execute.
func TestAutoActuatorCanaryRequiresAllGates(t *testing.T) {
	it := eligibleIntent(t)

	t.Run("missing mode (shadow) ⇒ no execute", func(t *testing.T) {
		r, spy := liveSpyResponder()
		clk := &fakeGraceClock{}
		grace := NewGraceQueue(r, time.Minute, clk)
		aa := NewAutoActuator(r, grace, []string{actionWouldQuarantine})
		aa.ActOn(it, ModeShadow)
		clk.fireAll()
		if atomic.LoadInt64(&spy.calls) != 0 {
			t.Fatal("shadow mode must never execute even with arm + grace")
		}
	})

	t.Run("missing arm (canary, action NOT armed) ⇒ dry-run, no execute", func(t *testing.T) {
		r, spy := liveSpyResponder()
		clk := &fakeGraceClock{}
		grace := NewGraceQueue(r, time.Minute, clk)
		aa := NewAutoActuator(r, grace, nil /* nothing armed */)
		res := aa.ActOn(it, ModeCanary)
		if res.Executed || !res.DryRun {
			t.Fatalf("an un-armed action in canary must stay dry-run, got %+v", res)
		}
		clk.fireAll() // even if a timer somehow existed
		if atomic.LoadInt64(&spy.calls) != 0 {
			t.Fatalf("an un-armed action must NOT reach the executor, got %d", spy.calls)
		}
		if grace.Pending() != 0 {
			t.Errorf("an un-armed (dry-run) action must not be grace-enqueued, pending=%d", grace.Pending())
		}
	})

	t.Run("missing grace expiry (enqueued, not fired) ⇒ no execute yet", func(t *testing.T) {
		r, spy := liveSpyResponder()
		clk := &fakeGraceClock{}
		grace := NewGraceQueue(r, time.Minute, clk)
		aa := NewAutoActuator(r, grace, []string{actionWouldQuarantine})
		res := aa.ActOn(it, ModeCanary)
		if res.Executed {
			t.Fatal("ActOn must DEFER execution to grace expiry, not execute inline")
		}
		if grace.Pending() != 1 {
			t.Fatalf("an armed canary action must be grace-enqueued, pending=%d", grace.Pending())
		}
		// Before the grace timer fires, nothing has executed.
		if atomic.LoadInt64(&spy.calls) != 0 {
			t.Fatalf("nothing should execute before grace expiry, got %d", spy.calls)
		}
	})

	t.Run("all gates present (canary + armed + grace expiry) ⇒ executes once", func(t *testing.T) {
		r, spy := liveSpyResponder()
		clk := &fakeGraceClock{}
		grace := NewGraceQueue(r, time.Minute, clk)
		aa := NewAutoActuator(r, grace, []string{actionWouldQuarantine})
		aa.ActOn(it, ModeCanary)
		clk.fireAll() // grace window elapses → APPLY
		if got := atomic.LoadInt64(&spy.calls); got != 1 {
			t.Fatalf("with ALL gates present, the action should execute exactly once, got %d", got)
		}
	})
}

// TestNewAutoActuatorRequiresGrace (N1) is the fail-closed construction guard: a
// nil GraceQueue must PANIC at construction — a live forward with no veto window is
// a design violation (the operator would have no chance to CANCEL a destructive
// auto-action). The earlier comment claimed a "test that omits the grace queue"
// covered the no-grace path; it did not (no such test existed) — this is it.
func TestNewAutoActuatorRequiresGrace(t *testing.T) {
	r, _ := liveSpyResponder()
	t.Run("nil grace panics (fail-closed)", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("NewAutoActuator with a nil grace queue must PANIC (a live forward must have a veto window)")
			}
		}()
		_ = NewAutoActuator(r, nil, []string{actionWouldQuarantine})
	})
	t.Run("nil responder panics (fail-closed)", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("NewAutoActuator with a nil responder must PANIC")
			}
		}()
		grace := NewGraceQueue(r, time.Minute, &fakeGraceClock{})
		_ = NewAutoActuator(nil, grace, nil)
	})
}

// TestActOnRefusesWithNilGrace (N1) pins the runtime fail-closed: even a
// hand-built actuator that bypassed the constructor and has a nil grace must NOT
// execute a forward in canary — ActOn REFUSES (no Execute) rather than running an
// un-windowed destructive action.
func TestActOnRefusesWithNilGrace(t *testing.T) {
	it := eligibleIntent(t)
	r, spy := liveSpyResponder()
	// Bypass the constructor (which would panic) to fabricate the nil-grace actuator.
	aa := &AutoActuator{resp: r, grace: nil, armed: map[string]bool{actionWouldQuarantine: true}}
	res := aa.ActOn(it, ModeCanary)
	if res.Executed {
		t.Fatal("ActOn with a nil grace must NOT execute a forward (fail-closed)")
	}
	if !strings.Contains(res.Detail, "REFUSED") {
		t.Errorf("the no-grace refusal should say REFUSED, got %q", res.Detail)
	}
	if got := atomic.LoadInt64(&spy.calls); got != 0 {
		t.Fatalf("a nil-grace forward must never reach the executor, got %d", got)
	}
}

// A kill-switch present REFUSES even a fully-gated canary action (the Responder's
// existing brake still applies on the auto path).
func TestAutoActuatorKillSwitchStillBrakes(t *testing.T) {
	it := eligibleIntent(t)
	spy := &spyExecutor{}
	r := NewResponder(spy, NewAuditLog(&bytes.Buffer{}), false, graceGuards(), func() time.Time { return testNow }).
		WithKillSwitch("/run/agentd/response.disabled", func(string) bool { return true /* present */ })
	clk := &fakeGraceClock{}
	grace := NewGraceQueue(r, time.Minute, clk)
	aa := NewAutoActuator(r, grace, []string{actionWouldQuarantine})

	aa.ActOn(it, ModeCanary)
	clk.fireAll()
	if atomic.LoadInt64(&spy.calls) != 0 {
		t.Fatalf("the kill-switch must brake the auto path too; spy saw %d calls", spy.calls)
	}
}
