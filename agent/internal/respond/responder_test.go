package respond

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedClock returns a deterministic injected clock.
func fixedClock() func() time.Time {
	ts := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return ts }
}

func decodeAudit(t *testing.T, b []byte) []AuditRecord {
	t.Helper()
	var recs []AuditRecord
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" {
			continue
		}
		var r AuditRecord
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("bad audit line %q: %v", ln, err)
		}
		recs = append(recs, r)
	}
	return recs
}

func TestDefaultIsDryRun(t *testing.T) {
	// A Responder built the way the agent builds it when ResponseEnabled is unset
	// (dryRun=true) must never call the executor.
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true, testGuards(), fixedClock())
	if !r.DryRun {
		t.Fatal("default responder should be dry-run")
	}
	res := r.Respond(Request{Action: ActionKill, Target: "1234"})
	if !res.DryRun || !res.OK {
		t.Fatalf("dry-run kill result=%+v", res)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("dry-run must NOT call executor, got %d calls", fake.CallCount())
	}
}

func TestDryRunAuditsButDoesNotExecute(t *testing.T) {
	var buf bytes.Buffer
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&buf), true, testGuards(), fixedClock())

	res := r.Respond(Request{Action: ActionIsolate, Target: "wlan0", Reason: "c2 beacon", Actor: "max"})
	if fake.CallCount() != 0 {
		t.Fatalf("executor called in dry-run: %d", fake.CallCount())
	}
	if !strings.Contains(res.Detail, "dry-run") {
		t.Errorf("detail should mark dry-run: %q", res.Detail)
	}
	recs := decodeAudit(t, buf.Bytes())
	if len(recs) != 2 {
		t.Fatalf("expected intent+result records, got %d", len(recs))
	}
	if recs[0].Stage != "intent" || recs[1].Stage != "result" {
		t.Errorf("stages=%q,%q", recs[0].Stage, recs[1].Stage)
	}
	for _, rec := range recs {
		if !rec.DryRun || rec.Actor != "max" || rec.Reason != "c2 beacon" {
			t.Errorf("audit rec=%+v", rec)
		}
		if !rec.Time.Equal(fixedClock()()) {
			t.Errorf("injected clock not used: %v", rec.Time)
		}
	}
}

func TestLiveExecutePath(t *testing.T) {
	var buf bytes.Buffer
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&buf), false, testGuards(), fixedClock())

	res := r.Respond(Request{Action: ActionKill, Target: "9999", Reason: "fileless exec", Actor: "max"})
	if fake.CallCount() != 1 {
		t.Fatalf("live path should call executor once, got %d", fake.CallCount())
	}
	if res.DryRun {
		t.Error("live result should not be dry-run")
	}
	if !res.OK {
		t.Errorf("expected OK result, got %+v", res)
	}
	last, _ := fake.Last()
	if last.Target != "9999" {
		t.Errorf("executor got wrong request: %+v", last)
	}
	recs := decodeAudit(t, buf.Bytes())
	if len(recs) != 2 || recs[1].DryRun || !recs[1].OK {
		t.Errorf("live audit=%+v", recs)
	}
}

func TestRefusedRequestNeverExecutes(t *testing.T) {
	var buf bytes.Buffer
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&buf), false, testGuards(), fixedClock())

	// PID 1 is refused by the guard even though we are live.
	res := r.Respond(Request{Action: ActionKill, Target: "1"})
	if res.OK {
		t.Error("kill pid 1 should be refused")
	}
	if !strings.Contains(res.Detail, "refused") {
		t.Errorf("detail should say refused: %q", res.Detail)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("refused request must not execute, got %d calls", fake.CallCount())
	}
	recs := decodeAudit(t, buf.Bytes())
	if len(recs) != 2 || recs[1].OK {
		t.Errorf("refusal should still be audited intent+result with OK=false: %+v", recs)
	}
}

func TestExecutorErrorSurfaces(t *testing.T) {
	fake := &FakeExecutor{Err: errors.New("nft missing")}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), false, testGuards(), fixedClock())
	res := r.Respond(Request{Action: ActionIsolate, Target: "wlan0"})
	if res.OK {
		t.Error("executor error should make result not-OK")
	}
	if !strings.Contains(res.Detail, "nft missing") {
		t.Errorf("error not surfaced in detail: %q", res.Detail)
	}
}

func TestRespondAllActionsDryRun(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true, testGuards(), fixedClock())
	good := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	reqs := []Request{
		{Action: ActionKill, Target: "1234"},
		{Action: ActionIsolate, Target: "wlan0"},
		{Action: ActionQuarantine, Target: "/tmp/evil"},
		{Action: ActionRevokeKey, Target: "/home/max/.ssh/authorized_keys", Args: map[string]string{"fingerprint": "SHA256:x"}},
		{Action: ActionBlockHash, Target: good},
	}
	for _, req := range reqs {
		res := r.Respond(req)
		if !res.OK || !res.DryRun {
			t.Errorf("%s dry-run result=%+v", req.Action, res)
		}
		if res.Detail == "" {
			t.Errorf("%s should describe planned action", req.Action)
		}
	}
	if fake.CallCount() != 0 {
		t.Fatalf("dry-run across all actions must not execute, got %d", fake.CallCount())
	}
}

func TestNilClockFallsBackToTimeNow(t *testing.T) {
	r := NewResponder(&FakeExecutor{}, NewAuditLog(&bytes.Buffer{}), true, testGuards(), nil)
	before := time.Now()
	got := r.clock()
	if got.Before(before.Add(-time.Second)) {
		t.Errorf("nil clock should fall back to ~now, got %v", got)
	}
}

func TestNilAuditIsNoOp(t *testing.T) {
	// A Responder with no audit sink must still work (fail-safe), not panic.
	r := NewResponder(&FakeExecutor{}, nil, true, testGuards(), fixedClock())
	res := r.Respond(Request{Action: ActionKill, Target: "1234"})
	if !res.OK {
		t.Errorf("nil audit should not break Respond: %+v", res)
	}
}
