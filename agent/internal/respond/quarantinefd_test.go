package respond

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// FIX 4 (MAJOR) — quarantineFD validated the inode by fstat'ing the O_NOFOLLOW
// fd, then renamed by the PATH STRING after closing the fd, so the inode validated
// was not PROVABLY the inode moved (TOCTOU; checked != acted, §4.2 #17). The fix
// re-fstats the MOVED file by fd and compares (Ino,Dev) to the pre-move values,
// rolling back + refusing on mismatch. These tests drive the confirm helpers
// directly (the deterministic core of the swap detection) and prove the
// happy-path confirm holds.

// confirmMovedInode passes when the moved file IS the checked inode, and REFUSES
// when the (Ino,Dev) differ — exactly the rename-branch checked==acted guarantee.
func TestConfirmMovedInodeDetectsSwap(t *testing.T) {
	dir := t.TempDir()
	moved := filepath.Join(dir, "moved")
	if err := os.WriteFile(moved, []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Capture the genuine identity of the moved file.
	var real syscall.Stat_t
	if err := syscall.Lstat(moved, &real); err != nil {
		t.Fatal(err)
	}
	if err := confirmMovedInode(moved, real); err != nil {
		t.Fatalf("matching inode must confirm, got %v", err)
	}
	// A swapped target: the checked identity belongs to a DIFFERENT inode than the
	// one now on disk. Confirm must refuse.
	swapped := real
	swapped.Ino++ // simulate the inode that WAS checked != the inode now present
	err := confirmMovedInode(moved, swapped)
	if err == nil || !strings.Contains(err.Error(), "swap detected") {
		t.Fatalf("an inode swap between check and act must be detected, got %v", err)
	}
}

// copyConfirmedInode (cross-fs branch) refuses when src no longer holds the
// fstat'd identity, so an inode swap before the EXDEV copy is detected without
// touching it.
func TestCopyConfirmedInodeDetectsSwap(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	var real syscall.Stat_t
	if err := syscall.Lstat(src, &real); err != nil {
		t.Fatal(err)
	}
	// Wrong captured identity → refuse, leave src intact, write no dst.
	wrong := real
	wrong.Ino++
	if err := copyConfirmedInode(src, dst, wrong); err == nil || !strings.Contains(err.Error(), "swap detected") {
		t.Fatalf("a src inode swap must be detected, got %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a refused copy must not create dst")
	}
	if b, _ := os.ReadFile(src); string(b) != "real" {
		t.Errorf("a refused copy must leave src intact: %q", b)
	}
	// Correct identity → copies and removes src.
	if err := copyConfirmedInode(src, dst, real); err != nil {
		t.Fatalf("matching inode must copy, got %v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "real" {
		t.Errorf("confirmed copy should land at dst: %q", b)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("confirmed copy should remove src")
	}
}

// FIX 4 end-to-end (no-swap): the post-move inode confirm invoked by quarantineFD
// must PASS for a legitimate quarantine (no false refusal) — the checked inode is
// the moved inode. The deterministic swap-detection proof is the two helper tests
// above (confirmMovedInode / copyConfirmedInode); this guards against the fix
// breaking the legitimate path.
func TestQuarantineFDHappyPathPassesInodeConfirm(t *testing.T) {
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
	run = func(name string, args ...string) error { return nil }
	defer func() { run = orig }()

	g := DefaultGuards()
	g.QuarantineDir = qdir
	e := NewRealExecutor(g)
	e.proc = fakeProc{1337: {Exe: exe, UID: 1000, StartTime: 5000, Live: true}}

	res, err := e.quarantineFD(fdReq(1337, 5000, staging))
	if err != nil {
		t.Fatalf("happy-path (no swap) must pass the inode confirm, got %v", err)
	}
	if !res.OK {
		t.Errorf("happy-path result not OK: %+v", res)
	}
	// The moved file landed in quarantine; the source is gone (acted on the checked
	// inode).
	if _, err := os.Stat(exe); !os.IsNotExist(err) {
		t.Error("the checked inode should have been moved out of staging")
	}
	entries, _ := os.ReadDir(qdir)
	if len(entries) != 1 {
		t.Fatalf("want 1 quarantined file, got %d", len(entries))
	}
}

// FIX 4 end-to-end SWAP: an attacker swaps the target inode in the TOCTOU window
// between quarantineFD's fstat-confirmed open and the move. The post-move inode
// confirm must DETECT the mismatch, ROLL BACK (move the wrong file back), and
// REFUSE — so the executor never locks down the swapped-in inode. We inject the
// swap via the renameFn hook (replace the source with a DIFFERENT inode just
// before the real rename), modelling the exact checked != acted race.
func TestQuarantineFDDetectsInodeSwapAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(staging, "payload")
	if err := os.WriteFile(exe, []byte("checked-malware"), 0o755); err != nil {
		t.Fatal(err)
	}
	qdir := filepath.Join(dir, "quarantine")

	origRun := run
	run = func(name string, args ...string) error { return nil }
	defer func() { run = origRun }()

	// Swap hook: just before the real rename, replace the source path's inode with
	// a DIFFERENT file (e.g. an attacker-swapped-in legit binary). The move then
	// relocates the WRONG inode; the post-move confirm must catch it.
	origRename := renameFn
	renameFn = func(src, dst string) error {
		_ = os.Remove(src)
		if err := os.WriteFile(src, []byte("SWAPPED-LEGIT-BINARY"), 0o755); err != nil {
			return err
		}
		return origRename(src, dst)
	}
	defer func() { renameFn = origRename }()

	g := DefaultGuards()
	g.QuarantineDir = qdir
	e := NewRealExecutor(g)
	e.proc = fakeProc{1337: {Exe: exe, UID: 1000, StartTime: 5000, Live: true}}

	_, err := e.quarantineFD(fdReq(1337, 5000, staging))
	if err == nil || !strings.Contains(err.Error(), "swap detected") {
		t.Fatalf("an inode swap between check and act must be detected + refused, got err=%v", err)
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("a detected swap must be rolled back: %v", err)
	}
	// Rollback restored the swapped file to the original path; the quarantine dir is
	// empty (we did not lock down the wrong inode).
	if b, _ := os.ReadFile(exe); string(b) != "SWAPPED-LEGIT-BINARY" {
		t.Errorf("rollback should restore the moved file to src, got %q", b)
	}
	if entries, _ := os.ReadDir(qdir); len(entries) != 0 {
		t.Errorf("a refused (swapped) quarantine must leave the quarantine dir empty, got %d entries", len(entries))
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
