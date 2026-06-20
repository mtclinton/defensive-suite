package respond

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// mutableClock is an injectable clock the rate-limit tests advance by hand so the
// sliding window is deterministic.
type mutableClock struct{ t time.Time }

func (c *mutableClock) now() time.Time { return c.t }
func (c *mutableClock) advance(d time.Duration) {
	c.t = c.t.Add(d)
}

// TestKillSwitchRefusesEvenLive: with the kill-switch file present, a LIVE
// (DryRun=false) request is refused and the executor is NEVER called.
func TestKillSwitchRefusesEvenLive(t *testing.T) {
	var buf bytes.Buffer
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&buf), false /*live*/, testGuards(), fixedClock())
	r.WithKillSwitch("/run/agentd/response.disabled", func(string) bool { return true })

	res := r.Respond(Request{Action: ActionKill, Target: "1234", Actor: "max"})
	if res.OK {
		t.Errorf("kill-switch present must refuse, got OK result: %+v", res)
	}
	if !contains(res.Detail, "kill-switch") || !contains(res.Detail, "globally disabled") {
		t.Errorf("detail should name the kill-switch: %q", res.Detail)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("kill-switch must NOT call executor even when live, got %d calls", fake.CallCount())
	}
	// The refusal is audited (intent + result), and the result is not-OK.
	recs := decodeAudit(t, buf.Bytes())
	if len(recs) != 2 {
		t.Fatalf("expected intent+result audit, got %d", len(recs))
	}
	if recs[1].Stage != "result" || recs[1].OK {
		t.Errorf("kill-switch refusal should be audited with OK=false: %+v", recs[1])
	}
}

// TestKillSwitchRefusesDryRun: the kill-switch disarms response REGARDLESS of
// DryRun — a dry-run request is refused too (it's a global disable, not a
// live-only brake).
func TestKillSwitchRefusesDryRun(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true /*dry-run*/, testGuards(), fixedClock())
	r.WithKillSwitch("/run/agentd/response.disabled", func(string) bool { return true })

	res := r.Respond(Request{Action: ActionIsolate, Target: "wlan0"})
	if res.OK {
		t.Errorf("kill-switch should refuse even in dry-run, got %+v", res)
	}
	if !contains(res.Detail, "kill-switch") {
		t.Errorf("detail should name the kill-switch: %q", res.Detail)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("dry-run already never executes; got %d calls", fake.CallCount())
	}
}

// TestKillSwitchAbsentNormal: with the kill-switch absent, response behaves
// normally (the live path executes).
func TestKillSwitchAbsentNormal(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), false /*live*/, testGuards(), fixedClock())
	r.WithKillSwitch("/run/agentd/response.disabled", func(string) bool { return false })

	res := r.Respond(Request{Action: ActionKill, Target: "1234"})
	if !res.OK {
		t.Errorf("kill-switch absent should allow the action, got %+v", res)
	}
	if fake.CallCount() != 1 {
		t.Fatalf("kill-switch absent: live path should execute once, got %d", fake.CallCount())
	}
}

// TestEmptyKillSwitchPathDisablesCheck: an empty path means the kill-switch is
// not configured — the probe must not even be consulted.
func TestEmptyKillSwitchPathDisablesCheck(t *testing.T) {
	probed := false
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), false, testGuards(), fixedClock())
	r.WithKillSwitch("", func(string) bool { probed = true; return true })

	res := r.Respond(Request{Action: ActionKill, Target: "1234"})
	if probed {
		t.Error("empty kill-switch path must not consult the existence probe")
	}
	if !res.OK || fake.CallCount() != 1 {
		t.Errorf("empty kill-switch path should allow normally: %+v calls=%d", res, fake.CallCount())
	}
}

// TestRateLimitAllowsNThenRefuses: the limiter allows exactly N live executions
// within the window, refuses the (N+1)th, then recovers once the clock advances
// past the window.
func TestRateLimitAllowsNThenRefuses(t *testing.T) {
	const N = 3
	const window = 60 * time.Second
	clk := &mutableClock{t: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)}

	var buf bytes.Buffer
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&buf), false /*live*/, testGuards(), clk.now)
	r.WithRateLimit(N, window)

	// First N live kills all succeed and reach the executor.
	for i := 0; i < N; i++ {
		res := r.Respond(Request{Action: ActionKill, Target: "1234"})
		if !res.OK {
			t.Fatalf("request %d within budget should succeed: %+v", i+1, res)
		}
	}
	if fake.CallCount() != N {
		t.Fatalf("first %d should execute, got %d calls", N, fake.CallCount())
	}

	// The (N+1)th within the same window is refused and does NOT execute.
	res := r.Respond(Request{Action: ActionKill, Target: "1234"})
	if res.OK {
		t.Errorf("request N+1 should be rate-limited, got OK: %+v", res)
	}
	if !contains(res.Detail, "rate limit exceeded") {
		t.Errorf("detail should mention the rate limit: %q", res.Detail)
	}
	if fake.CallCount() != N {
		t.Fatalf("rate-limited request must not execute; call count jumped to %d", fake.CallCount())
	}

	// Advance the clock past the window: the old events age out, budget recovers.
	clk.advance(window + time.Second)
	res = r.Respond(Request{Action: ActionKill, Target: "1234"})
	if !res.OK {
		t.Errorf("after the window advances the limiter should recover: %+v", res)
	}
	if fake.CallCount() != N+1 {
		t.Fatalf("recovered request should execute (call %d), got %d", N+1, fake.CallCount())
	}

	// The refusal was audited with OK=false.
	recs := decodeAudit(t, buf.Bytes())
	var sawRefusal bool
	for _, rec := range recs {
		if rec.Stage == "result" && !rec.OK && contains(rec.Detail, "rate limit") {
			sawRefusal = true
		}
	}
	if !sawRefusal {
		t.Error("rate-limit refusal should be recorded in the audit log")
	}
}

// TestRateLimitDoesNotCountDryRun: dry-run is FREE — many dry-run requests must
// not consume rate budget, so the first live request still succeeds.
func TestRateLimitDoesNotCountDryRun(t *testing.T) {
	clk := &mutableClock{t: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)}
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true /*dry-run*/, testGuards(), clk.now)
	r.WithRateLimit(2, time.Minute)

	// Way more than the limit, all in dry-run — none should consume budget.
	for i := 0; i < 10; i++ {
		res := r.Respond(Request{Action: ActionKill, Target: "1234"})
		if !res.OK || !res.DryRun {
			t.Fatalf("dry-run request %d should always succeed: %+v", i+1, res)
		}
	}
	if fake.CallCount() != 0 {
		t.Fatalf("dry-run must never execute, got %d", fake.CallCount())
	}
}

// TestRefusedGuardDoesNotConsumeRate: a request refused by the guards must not
// consume rate budget (the limiter only counts ALLOWED live executions).
func TestRefusedGuardDoesNotConsumeRate(t *testing.T) {
	clk := &mutableClock{t: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)}
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), false /*live*/, testGuards(), clk.now)
	r.WithRateLimit(1, time.Minute)

	// A guard-refused request (PID 1) must not eat the single budget slot.
	if res := r.Respond(Request{Action: ActionKill, Target: "1"}); res.OK {
		t.Fatalf("kill pid 1 should be refused by the guard: %+v", res)
	}
	// The one real budget slot is still available.
	if res := r.Respond(Request{Action: ActionKill, Target: "1234"}); !res.OK {
		t.Errorf("guard refusal should not have consumed rate budget: %+v", res)
	}
	if fake.CallCount() != 1 {
		t.Fatalf("exactly one live execution expected, got %d", fake.CallCount())
	}
}

// TestKillSwitchBeforeRateLimit: when both fire, the kill-switch wins and the
// rate limiter is not even consulted (so a disarmed responder doesn't burn
// budget). We verify by checking the detail names the kill-switch.
func TestKillSwitchBeforeRateLimit(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), false, testGuards(), fixedClock())
	r.WithKillSwitch("/run/agentd/response.disabled", func(string) bool { return true })
	r.WithRateLimit(1, time.Minute)

	res := r.Respond(Request{Action: ActionKill, Target: "1234"})
	if res.OK || !contains(res.Detail, "kill-switch") {
		t.Errorf("kill-switch should take precedence: %+v", res)
	}
	// Budget untouched: with the kill-switch gone, the next live request succeeds.
	r.WithKillSwitch("/run/agentd/response.disabled", func(string) bool { return false })
	if res := r.Respond(Request{Action: ActionKill, Target: "1234"}); !res.OK {
		t.Errorf("rate budget should be intact after a kill-switch refusal: %+v", res)
	}
}

// contains is a thin alias for strings.Contains used throughout the brake tests.
func contains(s, sub string) bool { return strings.Contains(s, sub) }
