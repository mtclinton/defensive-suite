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
		{"under quarantine dir, staging origin", "/var/lib/agentd/quarantine/123-payload", "/tmp/.x/payload", true},
		{"target NOT under quarantine dir", "/etc/passwd", "/tmp/x", false},
		{"target relative", "quarantine/x", "/tmp/x", false},
		{"empty target", "", "/tmp/x", false},
		{"missing origin", "/var/lib/agentd/quarantine/123-payload", "", false},
		{"relative origin", "/var/lib/agentd/quarantine/123-payload", "tmp/x", false},
		{"origin into critical path refused", "/var/lib/agentd/quarantine/123-passwd", "/etc/passwd", false},
		{"origin into /usr refused", "/var/lib/agentd/quarantine/x", "/usr/bin/ls", false},
		{"origin in /dev/shm staging allowed", "/var/lib/agentd/quarantine/x", "/dev/shm/.x/payload", true},
		{"origin in /var/tmp staging allowed", "/var/lib/agentd/quarantine/x", "/var/tmp/build/payload", true},
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

// FIX 1 (MAJOR) — unquarantine can clobber arbitrary sensitive files.
// The OLD validateUnquarantine reused validateQuarantine's CriticalPaths denylist
// (a quarantine-SOURCE filter) as the restore-DESTINATION filter, so an
// authenticated socket caller could set origin to /root/.bashrc,
// /home/<u>/.ssh/authorized_keys, or /var/spool/cron/crontabs/root — none under
// the denylist — and have executor.unquarantine os.Rename CLOBBER that live file
// with attacker-quarantined content (persistence / code-exec). The fix constrains
// the origin to a POSITIVE StagingDir allowlist. These paths MUST now be refused.
func TestValidateUnquarantineRefusesSensitiveDestinations(t *testing.T) {
	g := reverseGuards()
	const dst = "/var/lib/agentd/quarantine/123-evil"
	refused := []struct {
		name   string
		origin string
	}{
		{"root dotfile", "/root/.bashrc"},
		{"root authorized_keys", "/root/.ssh/authorized_keys"},
		{"home authorized_keys", "/home/max/.ssh/authorized_keys"},
		{"cron spool", "/var/spool/cron/crontabs/root"},
		{"etc shadow", "/etc/shadow"},
		{"opt app binary", "/opt/myapp/bin/server"},
		{"srv data", "/srv/www/index.html"},
		{"var lib not staging", "/var/lib/something/x"},
	}
	for _, c := range refused {
		t.Run("refuse "+c.name, func(t *testing.T) {
			req := Request{Action: ActionUnquarantine, Target: dst, Args: map[string]string{"origin": c.origin}}
			if err := g.Validate(req); err == nil {
				t.Fatalf("unquarantine origin %q MUST be refused (not staging-resident), got nil", c.origin)
			}
		})
	}
	// A StagingDir origin (the only legitimate auto-undo origin per §4.2/G5) is
	// allowed — the manual reverse of a quarantine of a staged file.
	for _, origin := range []string{"/tmp/.x/payload", "/dev/shm/dropper", "/var/tmp/cargo123/bin"} {
		req := Request{Action: ActionUnquarantine, Target: dst, Args: map[string]string{"origin": origin}}
		if err := g.Validate(req); err != nil {
			t.Errorf("staging origin %q should be allowed, got %v", origin, err)
		}
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

// FIX 1 (executor branch) — unquarantine must REFUSE if the origin already
// EXISTS so undo never CLOBBERS a live file. A quarantine of X then a recreated X
// (a different, legitimate inode now living at the origin) must not be silently
// overwritten by the restore.
func TestRealUnquarantineRefusesExistingOrigin(t *testing.T) {
	dir := t.TempDir()
	qdir := filepath.Join(dir, "quarantine")
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(qdir, "123-payload")
	if err := os.WriteFile(dst, []byte("quarantined-malware"), 0o000); err != nil {
		t.Fatal(err)
	}
	// A LIVE file already sits at the origin — restoring must refuse, not clobber.
	origin := filepath.Join(dir, "live", "payload")
	if err := os.MkdirAll(filepath.Dir(origin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(origin, []byte("LEGITIMATE-LIVE-CONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := run
	run = func(name string, args ...string) error { return nil }
	defer func() { run = orig }()

	e := NewRealExecutor(reverseGuards())
	_, err := e.unquarantine(Request{Action: ActionUnquarantine, Target: dst, Args: map[string]string{"origin": origin}})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unquarantine over an existing origin must be refused, got err=%v", err)
	}
	// The live file is UNTOUCHED.
	if b, _ := os.ReadFile(origin); string(b) != "LEGITIMATE-LIVE-CONTENT" {
		t.Errorf("refused unquarantine must not clobber the live origin: %q", b)
	}
	// The quarantined copy is still in place (the move never happened).
	if _, err := os.Stat(dst); err != nil {
		t.Errorf("refused unquarantine should leave the quarantined copy in place: %v", err)
	}
}

// FIX 2 (executor branch) — unquarantine os.Rename(dst, origin) FOLLOWS a symlink
// at the destination. A pre-planted symlinked PARENT of the origin (e.g.
// /staging/.ssh -> /root/.ssh) would redirect the restore to a privileged dir.
// The executor Lstats the origin parent and refuses a symlinked parent; the
// symlink target file must be left UNTOUCHED.
func TestRealUnquarantineRefusesSymlinkedOriginParent(t *testing.T) {
	dir := t.TempDir()
	qdir := filepath.Join(dir, "quarantine")
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(qdir, "123-authorized_keys")
	if err := os.WriteFile(dst, []byte("ssh-ed25519 ATTACKER implant\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	// The privileged dir the attacker wants the restore redirected INTO.
	privDir := filepath.Join(dir, "root", ".ssh")
	if err := os.MkdirAll(privDir, 0o700); err != nil {
		t.Fatal(err)
	}
	privFile := filepath.Join(privDir, "authorized_keys")
	if err := os.WriteFile(privFile, []byte("ssh-ed25519 LEGIT operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Staging dir whose .ssh leaf is a SYMLINK to the privileged dir.
	stagingSSH := filepath.Join(dir, "staging", ".ssh")
	if err := os.MkdirAll(filepath.Dir(stagingSSH), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(privDir, stagingSSH); err != nil {
		t.Fatal(err)
	}
	origin := filepath.Join(stagingSSH, "authorized_keys") // origin parent is a symlink

	orig := run
	run = func(name string, args ...string) error { return nil }
	defer func() { run = orig }()

	e := NewRealExecutor(reverseGuards())
	_, err := e.unquarantine(Request{Action: ActionUnquarantine, Target: dst, Args: map[string]string{"origin": origin}})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("unquarantine into a symlinked origin parent must be refused, got err=%v", err)
	}
	// The privileged authorized_keys is UNTOUCHED — the implant did not land.
	if b, _ := os.ReadFile(privFile); string(b) != "ssh-ed25519 LEGIT operator\n" {
		t.Errorf("symlink redirect must not touch the privileged file: %q", b)
	}
}

// FIX 2 — restoreKey os.WriteFile FOLLOWS a symlink at the path. A pre-planted
// authorized_keys symlink (e.g. /staging/.ssh/authorized_keys ->
// /root/.ssh/authorized_keys, with a sibling .dsuite.bak) would redirect the
// write to a privileged file (SSH-key implantation). The executor opens the dest
// O_NOFOLLOW + Lstats the leaf, refuses a symlink, and leaves the target UNTOUCHED.
func TestRealRestoreKeyRefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	// The privileged file the attacker wants implanted.
	privFile := filepath.Join(dir, "root", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(privFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privFile, []byte("ssh-ed25519 LEGIT operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlinked restore target pointing at the privileged file, with a sibling
	// .dsuite.bak carrying the attacker key.
	stage := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(stage, "authorized_keys")
	if err := os.Symlink(privFile, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+".dsuite.bak", []byte("ssh-ed25519 ATTACKER implant\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := run
	run = func(name string, args ...string) error { return nil }
	defer func() { run = orig }()

	e := NewRealExecutor(reverseGuards())
	_, err := e.restoreKey(Request{Action: ActionRestoreKey, Target: keyPath})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("restore-key onto a symlink must be refused, got err=%v", err)
	}
	// The privileged file is UNTOUCHED — the implant did not land through the link.
	if b, _ := os.ReadFile(privFile); string(b) != "ssh-ed25519 LEGIT operator\n" {
		t.Errorf("O_NOFOLLOW refusal must not touch the symlink target: %q", b)
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
