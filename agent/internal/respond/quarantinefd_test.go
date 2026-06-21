package respond

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// --- §3.2/§4.2 identity-bound, fd-based quarantine: GUARD validation ---

func TestValidateQuarantineFD(t *testing.T) {
	g := DefaultGuards()
	mk := func(target, starttime, staging, exe string) Request {
		args := map[string]string{}
		if starttime != "" {
			args["starttime"] = starttime
		}
		if staging != "" {
			args["staging_dirs"] = staging
		}
		if exe != "" {
			args["exe"] = exe
		}
		return Request{Action: ActionQuarantineFD, Target: target, Args: args}
	}
	cases := []struct {
		name string
		req  Request
		ok   bool
	}{
		{"valid identity-bound request", mk("1337", "5000", "/tmp/,/dev/shm/", "/tmp/.x/payload"), true},
		{"non-numeric pid", mk("abc", "5000", "/tmp/", ""), false},
		{"pid <=1", mk("1", "5000", "/tmp/", ""), false},
		{"missing starttime", mk("1337", "", "/tmp/", ""), false},
		{"missing staging constraint", mk("1337", "5000", "", ""), false},
		{"captured exe under /usr refused", mk("1337", "5000", "/tmp/", "/usr/bin/ls"), false},
		{"captured exe under /lib refused", mk("1337", "5000", "/tmp/", "/lib64/ld.so"), false},
		{"captured exe in staging ok", mk("1337", "5000", "/tmp/", "/tmp/.x/payload"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := g.Validate(c.req)
			if (err == nil) != c.ok {
				t.Errorf("Validate err=%v want ok=%v", err, c.ok)
			}
		})
	}
}

// --- the RealExecutor's RE-RESOLVE-and-REFUSE logic (identity bind) ---
// RealExecutor.Execute is never invoked in tests; these drive quarantineFD
// directly with an injected fake /proc resolver so the identity-bind refusals are
// exercised WITHOUT a real process or any actuator. The `run` choke point is
// swapped for a no-op so no chattr ever shells out.

func fdReq(pid int, starttime uint64, staging string) Request {
	return Request{
		Action: ActionQuarantineFD,
		Target: strconv.Itoa(pid),
		Args: map[string]string{
			"starttime":    strconv.FormatUint(starttime, 10),
			"staging_dirs": staging,
		},
	}
}

func TestQuarantineFDRefusesDeadProcess(t *testing.T) {
	e := NewRealExecutor(DefaultGuards())
	e.proc = fakeProc{} // pid 1337 not present → not live
	_, err := e.quarantineFD(fdReq(1337, 5000, "/tmp/"))
	if err == nil || !strings.Contains(err.Error(), "no longer live") {
		t.Fatalf("dead process must be refused, got err=%v", err)
	}
}

func TestQuarantineFDRefusesStartTimeMismatch(t *testing.T) {
	e := NewRealExecutor(DefaultGuards())
	// live process exists, but its starttime differs from the captured one (PID
	// reuse / TOCTOU): a different process now holds the PID.
	e.proc = fakeProc{1337: {Exe: "/tmp/.x/payload", UID: 1000, StartTime: 9999, Live: true}}
	_, err := e.quarantineFD(fdReq(1337, 5000, "/tmp/"))
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("starttime mismatch must be refused, got err=%v", err)
	}
}

func TestQuarantineFDRefusesExecIDMismatch(t *testing.T) {
	e := NewRealExecutor(DefaultGuards())
	e.proc = fakeProc{1337: {Exe: "/tmp/.x/payload", UID: 1000, StartTime: 5000, ExecID: "OTHER", Live: true}}
	req := fdReq(1337, 5000, "/tmp/")
	req.Args["exec_id"] = "c"
	_, err := e.quarantineFD(req)
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("exec_id mismatch must be refused, got err=%v", err)
	}
}

func TestQuarantineFDRefusesOutsideStagingDir(t *testing.T) {
	e := NewRealExecutor(DefaultGuards())
	// identity matches, but the live exe is a forged /opt path: REFUSE (the §3.2
	// constraint that collapses the DoS-via-defender surface).
	e.proc = fakeProc{1337: {Exe: "/opt/app/server", UID: 1000, StartTime: 5000, Live: true}}
	_, err := e.quarantineFD(fdReq(1337, 5000, "/tmp/"))
	if err == nil || !strings.Contains(err.Error(), "not under a staging dir") {
		t.Fatalf("an out-of-staging exe must be refused, got err=%v", err)
	}
}

// The happy path: identity matches, exe is staging-resident AND a real on-disk
// file under a temp "staging" dir. The executor opens it O_NOFOLLOW, fstats by
// fd, and moves it to the quarantine dir — the file checked is the file acted on.
func TestQuarantineFDHappyPathActsByFD(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(staging, "payload")
	if err := os.WriteFile(exe, []byte("malware"), 0o755); err != nil {
		t.Fatal(err)
	}
	qdir := filepath.Join(dir, "quarantine")

	orig := run
	run = func(name string, args ...string) error { return nil } // no chattr shell-out
	defer func() { run = orig }()

	g := DefaultGuards()
	g.QuarantineDir = qdir
	e := NewRealExecutor(g)
	e.proc = fakeProc{1337: {Exe: exe, UID: 1000, StartTime: 5000, Live: true}}

	res, err := e.quarantineFD(fdReq(1337, 5000, staging))
	if err != nil {
		t.Fatalf("happy-path quarantine-fd: %v", err)
	}
	if !res.OK || res.Undo == "" {
		t.Errorf("result should be OK + reversible: %+v", res)
	}
	if _, err := os.Stat(exe); !os.IsNotExist(err) {
		t.Error("the live exe should have been moved out of staging")
	}
	// Exactly one file landed in the quarantine dir.
	entries, _ := os.ReadDir(qdir)
	if len(entries) != 1 {
		t.Fatalf("want 1 quarantined file, got %d", len(entries))
	}
	if !strings.Contains(res.Detail, "identity-bound") || !strings.Contains(res.Detail, "inode") {
		t.Errorf("detail should record the identity bind + fstat inode: %q", res.Detail)
	}
}

// O_NOFOLLOW behavior: when the resolved exe is a SYMLINK, the executor's
// O_NOFOLLOW open refuses it (a swapped-in symlink cannot redirect the act). The
// identity + staging gates pass; only the O_NOFOLLOW open is exercised here.
func TestQuarantineFDRefusesSymlinkONOFOLLOW(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(dir, "real-target")
	if err := os.WriteFile(realFile, []byte("legit"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(staging, "payload")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatal(err)
	}

	orig := run
	run = func(name string, args ...string) error { return nil }
	defer func() { run = orig }()

	g := DefaultGuards()
	g.QuarantineDir = filepath.Join(dir, "quarantine")
	e := NewRealExecutor(g)
	// resolver returns the symlink path as the "exe" (staging-resident).
	e.proc = fakeProc{1337: {Exe: link, UID: 1000, StartTime: 5000, Live: true}}

	_, err := e.quarantineFD(fdReq(1337, 5000, staging))
	if err == nil || !strings.Contains(err.Error(), "O_NOFOLLOW") {
		t.Fatalf("a symlink exe must be refused by O_NOFOLLOW, got err=%v", err)
	}
	// The symlink target must be untouched (the act was refused, not redirected).
	if b, _ := os.ReadFile(realFile); string(b) != "legit" {
		t.Errorf("O_NOFOLLOW refusal must not touch the symlink target: %q", b)
	}
}

// quarantine-fd is dry-run by default through the responder + guarded (a bad
// identity-bound request is refused before any executor is reached).
func TestQuarantineFDDryRunByDefault(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(nil), true, DefaultGuards(), fixedClock())
	res := r.Respond(fdReq(1337, 5000, "/tmp/"))
	if !res.OK || !res.DryRun {
		t.Errorf("quarantine-fd dry-run result=%+v", res)
	}
	if fake.CallCount() != 0 {
		t.Fatalf("dry-run must not execute, got %d calls", fake.CallCount())
	}
}
