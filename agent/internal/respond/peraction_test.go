package respond

import (
	"bytes"
	"testing"
	"time"
)

// --- §4.4 PER-ACTION arming: one action live while the responder default is dry ---

func boolPtr(b bool) *bool { return &b }

// A single responder defaulting to DRY-RUN runs ONE per-Request-live action live
// (reaching the executor) while every other request stays dry (never reaching it).
// No second executor; the same validated pipeline is used for both.
func TestPerActionLiveWhileDefaultDry(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true /* default DRY */, testGuards(), fixedClock())

	// Default (no per-Request override) → dry-run: executor NOT reached.
	dry := r.Respond(Request{Action: ActionQuarantine, Target: "/tmp/evil"})
	if !dry.DryRun || !dry.OK {
		t.Errorf("default request should stay dry-run: %+v", dry)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("dry default must not execute, got %d", fake.CallCount())
	}

	// Per-Request live override → executes once, NOT dry-run.
	live := r.Respond(Request{Action: ActionQuarantine, Target: "/tmp/evil2", DryRun: boolPtr(false)})
	if live.DryRun {
		t.Errorf("per-action-live request must not be dry-run: %+v", live)
	}
	if fake.CallCount() != 1 {
		t.Fatalf("per-action-live request should execute once, got %d", fake.CallCount())
	}

	// A subsequent default request stays dry again (the override is per-request).
	dry2 := r.Respond(Request{Action: ActionQuarantine, Target: "/tmp/evil3"})
	if !dry2.DryRun {
		t.Errorf("default request after a live one must still be dry-run: %+v", dry2)
	}
	if fake.CallCount() != 1 {
		t.Fatalf("default request must not execute, count=%d", fake.CallCount())
	}
}

// The reverse: a LIVE responder can force a SINGLE action DRY via a per-Request
// override (so the auto path can shadow one action while others run live).
func TestPerActionDryWhileDefaultLive(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), false /* default LIVE */, testGuards(), fixedClock())

	dryOverride := r.Respond(Request{Action: ActionKill, Target: "1234", DryRun: boolPtr(true)})
	if !dryOverride.DryRun {
		t.Errorf("per-action-dry override on a live responder should be dry-run: %+v", dryOverride)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("per-action-dry override must not execute, got %d", fake.CallCount())
	}
}

// A per-action-LIVE request is NOT exempt from the kill-switch: the shared brake
// still refuses it (no bypass).
func TestPerActionLiveStillHitsKillSwitch(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true, testGuards(), fixedClock())
	r.WithKillSwitch("/run/agentd/response.disabled", func(string) bool { return true }) // switch is ON

	res := r.Respond(Request{Action: ActionQuarantine, Target: "/tmp/evil", DryRun: boolPtr(false)})
	if res.OK {
		t.Error("kill-switch must refuse a per-action-live request")
	}
	if fake.CallCount() != 0 {
		t.Fatalf("kill-switch must prevent execution of a per-action-live request, got %d", fake.CallCount())
	}
}

// A per-action-LIVE request is NOT exempt from the rate limit: the SAME limiter
// applies (no separate budget, no bypass). With a 1/window limit, the first
// per-action-live action runs and the second is refused.
func TestPerActionLiveStillHitsRateLimit(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true, testGuards(), fixedClock())
	r.WithRateLimit(1, time.Minute)

	first := r.Respond(Request{Action: ActionQuarantine, Target: "/tmp/a", DryRun: boolPtr(false)})
	if !first.OK {
		t.Fatalf("first per-action-live action should run: %+v", first)
	}
	second := r.Respond(Request{Action: ActionQuarantine, Target: "/tmp/b", DryRun: boolPtr(false)})
	if second.OK {
		t.Error("the rate limit must refuse a second per-action-live action in-window")
	}
	if fake.CallCount() != 1 {
		t.Fatalf("rate limit should cap per-action-live at 1, got %d executor calls", fake.CallCount())
	}
}

// A per-action-LIVE request still goes through Validate: a guard-refused target
// never reaches the executor regardless of the live override.
func TestPerActionLiveStillValidates(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true, testGuards(), fixedClock())
	res := r.Respond(Request{Action: ActionKill, Target: "1" /* init */, DryRun: boolPtr(false)})
	if res.OK {
		t.Error("guard must refuse kill pid 1 even with a per-action-live override")
	}
	if fake.CallCount() != 0 {
		t.Fatalf("a guard-refused per-action-live request must not execute, got %d", fake.CallCount())
	}
}
