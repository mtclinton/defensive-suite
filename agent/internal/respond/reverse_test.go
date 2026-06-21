package respond

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- §4.6 reverse actuators: GUARDED, dry-run-by-default, structured ---

// reverseGuards returns guards with a known quarantine dir so unquarantine's
// "must be under the quarantine dir" check has a concrete root.
func reverseGuards() Guards {
	g := DefaultGuards()
	g.QuarantineDir = "/var/lib/agentd/quarantine"
	return g
}

func TestValidateUnquarantine(t *testing.T) {
	g := reverseGuards()
	cases := []struct {
		name   string
		target string
		origin string
		ok     bool
	}{
		{"under quarantine dir, abs origin", "/var/lib/agentd/quarantine/123-payload", "/tmp/.x/payload", true},
		{"target NOT under quarantine dir", "/etc/passwd", "/tmp/x", false},
		{"target relative", "quarantine/x", "/tmp/x", false},
		{"empty target", "", "/tmp/x", false},
		{"missing origin", "/var/lib/agentd/quarantine/123-payload", "", false},
		{"relative origin", "/var/lib/agentd/quarantine/123-payload", "tmp/x", false},
		{"origin into critical path refused", "/var/lib/agentd/quarantine/123-passwd", "/etc/passwd", false},
		{"origin into /usr refused", "/var/lib/agentd/quarantine/x", "/usr/bin/ls", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := Request{Action: ActionUnquarantine, Target: c.target, Args: map[string]string{"origin": c.origin}}
			err := g.Validate(req)
			if (err == nil) != c.ok {
				t.Errorf("Validate(%+v) err=%v, want ok=%v", req, err, c.ok)
			}
		})
	}
}

func TestValidateDeIsolateIsSafe(t *testing.T) {
	g := reverseGuards()
	// de-isolate restores egress; it can never self-lock-out, so it is always
	// permitted (no target requirement).
	if err := g.Validate(Request{Action: ActionDeIsolate}); err != nil {
		t.Errorf("de-isolate should be safe/permitted, got %v", err)
	}
	if err := g.Validate(Request{Action: ActionDeIsolate, Target: "anything"}); err != nil {
		t.Errorf("de-isolate with target should still be permitted, got %v", err)
	}
}

func TestValidateRestoreKey(t *testing.T) {
	g := reverseGuards()
	cases := []struct {
		name   string
		target string
		ok     bool
	}{
		{"authorized_keys", "/home/max/.ssh/authorized_keys", true},
		{"authorized_keys2", "/root/.ssh/authorized_keys2", true},
		{"not an authorized_keys file", "/etc/passwd", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := g.Validate(Request{Action: ActionRestoreKey, Target: c.target})
			if (err == nil) != c.ok {
				t.Errorf("restore-key Validate(%q) err=%v, want ok=%v", c.target, err, c.ok)
			}
		})
	}
}

// Each reverse actuator is DRY-RUN by default through a responder built the way
// the agent builds it (dryRun=true): it validates, audits, and returns the planned
// reverse WITHOUT ever calling the executor.
func TestReverseActionsDryRunByDefault(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true, reverseGuards(), fixedClock())
	reqs := []Request{
		{Action: ActionUnquarantine, Target: "/var/lib/agentd/quarantine/1-payload", Args: map[string]string{"origin": "/tmp/.x/payload"}},
		{Action: ActionDeIsolate},
		{Action: ActionRestoreKey, Target: "/home/max/.ssh/authorized_keys"},
	}
	for _, req := range reqs {
		res := r.Respond(req)
		if !res.OK || !res.DryRun {
			t.Errorf("%s dry-run result=%+v", req.Action, res)
		}
		if res.Detail == "" {
			t.Errorf("%s should describe the planned reverse", req.Action)
		}
	}
	if fake.CallCount() != 0 {
		t.Fatalf("reverse actions in dry-run must NOT execute, got %d calls", fake.CallCount())
	}
}

// A guarded BAD reverse target is refused before the executor is ever reached,
// even when live.
func TestReverseActionsGuardRefusesBadTargets(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), false /* live */, reverseGuards(), fixedClock())
	// unquarantine of a path NOT under the quarantine dir is refused.
	res := r.Respond(Request{Action: ActionUnquarantine, Target: "/etc/shadow", Args: map[string]string{"origin": "/tmp/x"}})
	if res.OK {
		t.Error("unquarantine of a non-quarantine-dir path must be refused")
	}
	if !strings.Contains(res.Detail, "refused") {
		t.Errorf("detail should say refused: %q", res.Detail)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("a refused reverse must not execute, got %d calls", fake.CallCount())
	}
}

// --- quarantine → unquarantine ROUND-TRIP via the responder + FakeExecutor ---

// A quarantine followed by its structured unquarantine inverse both flow through
// the validated pipeline (Validate → kill-switch → rate-limit → audit) and both
// reach the FakeExecutor live — proving the inverse is a first-class Request, not
// a shelled free-text string.
func TestQuarantineUnquarantineRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&buf), false /* live */, reverseGuards(), fixedClock())

	const origin = "/tmp/.x/payload"
	const dst = "/var/lib/agentd/quarantine/123-payload"

	// Forward: quarantine.
	fwd := r.Respond(Request{Action: ActionQuarantine, Target: origin, Reason: "c2 beacon", Actor: "max"})
	if !fwd.OK || fwd.DryRun {
		t.Fatalf("forward quarantine result=%+v", fwd)
	}

	// Inverse: a STRUCTURED unquarantine Request (Target=dst, origin=origin).
	inv := r.Respond(Request{Action: ActionUnquarantine, Target: dst, Args: map[string]string{"origin": origin}, Reason: "false positive", Actor: "max"})
	if !inv.OK || inv.DryRun {
		t.Fatalf("inverse unquarantine result=%+v", inv)
	}

	if fake.CallCount() != 2 {
		t.Fatalf("round-trip should call the executor twice, got %d", fake.CallCount())
	}
	calls := fake.Calls
	if calls[0].Action != ActionQuarantine || calls[1].Action != ActionUnquarantine {
		t.Errorf("executor calls = %q,%q want quarantine,unquarantine", calls[0].Action, calls[1].Action)
	}
	if calls[1].Target != dst || calls[1].arg("origin") != origin {
		t.Errorf("unquarantine call routed wrong target/origin: %+v", calls[1])
	}

	// Both intent+result of both actions are audited (a structured, attributable
	// trail — not a free-text shell string).
	recs := decodeAudit(t, buf.Bytes())
	if len(recs) != 4 {
		t.Fatalf("want 4 audit records (2 actions × intent+result), got %d", len(recs))
	}
}

// --- REAL reverse executors: the file-moving impls actually round-trip ---
// (RealExecutor.Execute is never invoked in tests; these call the per-action
// methods directly, with the `run` choke point swapped for a recorder so nothing
// shells out — only the real os.Rename / os.WriteFile work is exercised.)

func TestRealUnquarantineRestoresFile(t *testing.T) {
	dir := t.TempDir()
	qdir := filepath.Join(dir, "quarantine")
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(qdir, "123-payload")
	origin := filepath.Join(dir, "origin", "payload")
	if err := os.MkdirAll(filepath.Dir(origin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("malware"), 0o000); err != nil {
		t.Fatal(err)
	}

	orig := run
	run = func(name string, args ...string) error { return nil } // no chattr shell-out
	defer func() { run = orig }()

	e := NewRealExecutor(reverseGuards())
	res, err := e.unquarantine(Request{Action: ActionUnquarantine, Target: dst, Args: map[string]string{"origin": origin}})
	if err != nil {
		t.Fatalf("unquarantine: %v", err)
	}
	if !res.OK {
		t.Errorf("result not OK: %+v", res)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("quarantine dst should be gone after unquarantine")
	}
	if b, err := os.ReadFile(origin); err != nil || string(b) != "malware" {
		t.Errorf("origin contents=%q err=%v (want malware restored)", b, err)
	}
}

func TestRealRestoreKeyFromBackup(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "authorized_keys")
	backup := keyPath + ".dsuite.bak"
	if err := os.WriteFile(backup, []byte("ssh-ed25519 AAAA original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 BBBB revoked-to-empty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewRealExecutor(reverseGuards())
	res, err := e.restoreKey(Request{Action: ActionRestoreKey, Target: keyPath})
	if err != nil {
		t.Fatalf("restore-key: %v", err)
	}
	if !res.OK {
		t.Errorf("result not OK: %+v", res)
	}
	if b, _ := os.ReadFile(keyPath); string(b) != "ssh-ed25519 AAAA original\n" {
		t.Errorf("authorized_keys not restored from backup: %q", b)
	}
}

func TestRealDeIsolateDeletesTable(t *testing.T) {
	var cmds []string
	orig := run
	run = func(name string, args ...string) error {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return nil
	}
	defer func() { run = orig }()

	e := NewRealExecutor(Guards{})
	res, err := e.deIsolate(Request{Action: ActionDeIsolate})
	if err != nil {
		t.Fatalf("de-isolate: %v", err)
	}
	if !res.OK {
		t.Errorf("result not OK: %+v", res)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "nft delete table inet dsuite_isolate") {
		t.Errorf("de-isolate must delete the isolation table:\n%s", joined)
	}
}

// --- §4.6 auto-undo.jsonl journal: type + writer round-trip ---

func TestUndoJournalRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	j := NewUndoJournal(&buf)
	rec := UndoRecord{
		Time: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		Request: Request{
			Action: ActionQuarantineFD, Target: "1337",
			Args: map[string]string{"starttime": "5000", "staging_dirs": "/tmp/"},
		},
		Snapshot: UndoSnapshot{Pid: 1337, Exe: "/tmp/.x/payload", UID: 1000, StartTime: 5000, ExecID: "c"},
		Inverse: Request{
			Action: ActionUnquarantine, Target: "/var/lib/agentd/quarantine/1-payload",
			Args: map[string]string{"origin": "/tmp/.x/payload"},
		},
		Finding: UndoFinding{Check: "realtime.correlated", Technique: "T1041", Dst: "8.8.8.8:443", Related: []string{"resolved=exec_id"}},
	}
	if err := j.Append(rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Exactly one JSON line.
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want 1 journal line, got %d", len(lines))
	}
	var got UndoRecord
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal journal line: %v", err)
	}
	if !got.Time.Equal(rec.Time) {
		t.Errorf("time not round-tripped: %v != %v", got.Time, rec.Time)
	}
	if got.Request.Action != ActionQuarantineFD || got.Inverse.Action != ActionUnquarantine {
		t.Errorf("request/inverse not round-tripped: %+v / %+v", got.Request, got.Inverse)
	}
	if got.Snapshot.Exe != "/tmp/.x/payload" || got.Snapshot.StartTime != 5000 {
		t.Errorf("snapshot not round-tripped: %+v", got.Snapshot)
	}
	if got.Finding.Check != "realtime.correlated" || got.Finding.Dst != "8.8.8.8:443" {
		t.Errorf("finding context not round-tripped: %+v", got.Finding)
	}
}

func TestUndoJournalNilSafe(t *testing.T) {
	var j *UndoJournal
	if err := j.Append(UndoRecord{}); err != nil {
		t.Errorf("nil journal Append should be a no-op, got %v", err)
	}
	j2 := NewUndoJournal(nil)
	if err := j2.Append(UndoRecord{}); err != nil {
		t.Errorf("nil-writer journal Append should be a no-op, got %v", err)
	}
}
