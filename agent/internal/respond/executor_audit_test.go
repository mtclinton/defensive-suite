package respond

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFakeExecutorRecordsAndIsInert(t *testing.T) {
	f := &FakeExecutor{}
	if f.CallCount() != 0 {
		t.Fatal("fresh fake should have no calls")
	}
	if _, ok := f.Last(); ok {
		t.Fatal("fresh fake should have no last call")
	}
	req := Request{Action: ActionKill, Target: "5"}
	res, err := f.Execute(req)
	if err != nil {
		t.Fatalf("fake execute err: %v", err)
	}
	if !res.OK || res.Action != ActionKill || res.Target != "5" {
		t.Errorf("fake result=%+v", res)
	}
	if f.CallCount() != 1 {
		t.Errorf("call count=%d", f.CallCount())
	}
	last, ok := f.Last()
	if !ok || last.Target != "5" {
		t.Errorf("last=%+v ok=%v", last, ok)
	}
}

func TestFakeExecutorErrAndResultFn(t *testing.T) {
	f := &FakeExecutor{Err: errors.New("boom")}
	if _, err := f.Execute(Request{Action: ActionKill, Target: "5"}); err == nil {
		t.Error("expected forced error")
	}

	f2 := &FakeExecutor{ResultFn: func(r Request) Result {
		return Result{OK: true, Action: r.Action, Target: r.Target, Detail: "custom"}
	}}
	res, _ := f2.Execute(Request{Action: ActionIsolate, Target: "wlan0"})
	if res.Detail != "custom" {
		t.Errorf("ResultFn not used: %+v", res)
	}
}

func TestFakeExecutorConcurrent(t *testing.T) {
	f := &FakeExecutor{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.Execute(Request{Action: ActionKill, Target: "7"})
		}()
	}
	wg.Wait()
	if f.CallCount() != 50 {
		t.Errorf("concurrent calls=%d want 50", f.CallCount())
	}
}

func TestAuditLogWritesJSONLines(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf)
	now := time.Date(2026, 6, 19, 1, 2, 3, 0, time.UTC)
	req := Request{Action: ActionQuarantine, Target: "/tmp/x", Reason: "malware", Actor: "max"}

	if err := a.Intent(now, req, true); err != nil {
		t.Fatal(err)
	}
	if err := a.Result(now, req, Result{OK: true, DryRun: true, Detail: "would move"}); err != nil {
		t.Fatal(err)
	}
	recs := decodeAudit(t, buf.Bytes())
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if recs[0].Stage != "intent" || recs[0].Action != ActionQuarantine || recs[0].Actor != "max" {
		t.Errorf("intent rec=%+v", recs[0])
	}
	if recs[1].Stage != "result" || !recs[1].OK || recs[1].Detail != "would move" {
		t.Errorf("result rec=%+v", recs[1])
	}
	if !recs[0].Time.Equal(now) {
		t.Errorf("injected time not recorded: %v", recs[0].Time)
	}
}

func TestAuditLogNilSafe(t *testing.T) {
	var a *AuditLog
	if err := a.Intent(time.Now(), Request{Action: ActionKill, Target: "1"}, true); err != nil {
		t.Errorf("nil audit log should be a no-op, got %v", err)
	}
	a2 := NewAuditLog(nil)
	if err := a2.Result(time.Now(), Request{}, Result{}); err != nil {
		t.Errorf("nil writer should be a no-op, got %v", err)
	}
}

func TestAuditLogConcurrentAppend(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.Intent(time.Now(), Request{Action: ActionKill, Target: "2"}, false)
		}()
	}
	wg.Wait()
	recs := decodeAudit(t, buf.Bytes())
	if len(recs) != 100 {
		t.Errorf("concurrent appends produced %d records (interleaving?)", len(recs))
	}
}

// TestRealExecutorExistsButNotRun documents that RealExecutor is constructible
// (it must compile and ship) without ever invoking its destructive Execute.
func TestRealExecutorConstructsButIsNeverRun(t *testing.T) {
	e := NewRealExecutor(DefaultGuards())
	if e.IsolateTable == "" {
		t.Error("real executor should set an isolate table name")
	}
	// We deliberately do NOT call e.Execute — nothing destructive runs in tests.
	var _ Executor = e
}

// TestIsolateKeepsManagementInterfaces pins the corrected isolate ruleset: the
// output chain DROPS by default and ACCEPTs the lifeline interfaces (loopback +
// the configured management ifaces), never the isolated target. It swaps the
// `run` choke point for a recorder, so nothing is executed — only the intended
// nft commands are captured. This is the regression test the original (all-drop,
// wrong-iface) rules lacked.
func TestIsolateKeepsManagementInterfaces(t *testing.T) {
	var cmds []string
	orig := run
	run = func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return nil
	}
	defer func() { run = orig }()

	e := NewRealExecutor(Guards{MgmtIfaces: []string{"lo", "tailscale0"}})
	res, err := e.isolate(Request{Action: ActionIsolate, Target: "wlan0"})
	if err != nil {
		t.Fatalf("isolate: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "policy drop") {
		t.Errorf("isolate must set a drop policy:\n%s", joined)
	}
	for _, want := range []string{"oifname lo accept", "oifname tailscale0 accept"} {
		if !strings.Contains(joined, want) {
			t.Errorf("isolate must keep the lifeline (%q missing):\n%s", want, joined)
		}
	}
	// Must NOT keep the isolated target iface, nor use the old all-dropping rule.
	if strings.Contains(joined, "wlan0") || strings.Contains(joined, "!=") {
		t.Errorf("isolate must not reference the isolated target / use the old rule:\n%s", joined)
	}
	if !res.OK || res.Undo == "" {
		t.Errorf("isolate result should be OK + reversible: %+v", res)
	}
}
