package x11lock

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
)

func TestParseLock(t *testing.T) {
	lf := ParseLock("/tmp/.X11-lock", 0, "     12345\n")
	if lf.Display != 11 {
		t.Errorf("display=%d", lf.Display)
	}
	if lf.PID != 12345 {
		t.Errorf("pid=%d", lf.PID)
	}
}

func TestParseLockBadContent(t *testing.T) {
	lf := ParseLock("/tmp/.X0-lock", 1000, "garbage")
	if lf.PID != -1 {
		t.Errorf("pid=%d want -1", lf.PID)
	}
	if lf.Display != 0 {
		t.Errorf("display=%d", lf.Display)
	}
}

func TestParseProcStatComm(t *testing.T) {
	if comm, ok := parseProcStatComm("4242 (Xorg) S 1 4242 4242 0"); !ok || comm != "Xorg" {
		t.Errorf("comm=%q ok=%v", comm, ok)
	}
	if comm, ok := parseProcStatComm("99 (weird (name)) S 1"); !ok || comm != "weird (name)" {
		t.Errorf("comm=%q ok=%v", comm, ok)
	}
	if _, ok := parseProcStatComm("no parens here"); ok {
		t.Error("should fail without parens")
	}
}

func TestEvaluate(t *testing.T) {
	procs := []Proc{
		{PID: 100, UID: 0, Comm: "Xorg"},
		{PID: 200, UID: 1000, Comm: "bash"},
	}
	xUIDs := map[int]bool{0: true}
	if _, susp := Evaluate(LockFile{Path: "/tmp/.X0-lock", PID: 100}, procs, xUIDs); susp {
		t.Error("a lock owned by a running Xorg at an allowed UID should not be suspicious")
	}
	if f, susp := Evaluate(LockFile{Path: "/tmp/.X0-lock", PID: 999}, procs, xUIDs); !susp || f.Severity != report.SeverityHigh {
		t.Errorf("non-running pid=%+v susp=%v", f, susp)
	}
	if f, susp := Evaluate(LockFile{Path: "/tmp/.X0-lock", PID: 200}, procs, xUIDs); !susp || f.Severity != report.SeverityHigh {
		t.Errorf("non-X-server pid=%+v susp=%v", f, susp)
	}
	if f, susp := Evaluate(LockFile{Path: "/tmp/.X0-lock", PID: -1}, procs, xUIDs); !susp || f.Severity != report.SeverityMedium {
		t.Errorf("invalid pid=%+v susp=%v", f, susp)
	}
}

// A process named "Xorg" but running under an unexpected UID is the spoof the
// comm-only check would miss; the UID gate must flag it.
func TestEvaluateRejectsSpoofedXorgUID(t *testing.T) {
	procs := []Proc{{PID: 100, UID: 1000, Comm: "Xorg"}}
	if f, susp := Evaluate(LockFile{Path: "/tmp/.X0-lock", PID: 100}, procs, map[int]bool{0: true}); !susp || f.Severity != report.SeverityHigh {
		t.Errorf("spoofed-UID Xorg should be flagged: %+v susp=%v", f, susp)
	}
	// With no UID allowlist, the UID gate is skipped (comm alone accepted).
	if _, susp := Evaluate(LockFile{Path: "/tmp/.X0-lock", PID: 100}, procs, map[int]bool{}); susp {
		t.Error("empty UID allowlist should skip the UID gate")
	}
}

func TestScanFallbackUIDAllowlist(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, ".X0-lock")
	if err := os.WriteFile(lock, []byte("12345\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	glob := filepath.Join(dir, ".X*-lock")
	noProc := filepath.Join(dir, "no-such-proc") // ReadDir fails -> haveProcs=false

	// Owner (current uid) is on the allowlist -> accepted silently.
	if f := Scan(glob, []int{os.Getuid()}, noProc); len(f) != 0 {
		t.Errorf("allowlisted owner should be accepted: %+v", f)
	}
	// Owner not allowlisted -> one Info finding (cannot verify).
	f := Scan(glob, []int{}, noProc)
	if len(f) != 1 || f[0].Severity != report.SeverityInfo {
		t.Errorf("non-allowlisted owner should yield Info: %+v", f)
	}
}

func TestScanRejectsNonRegularLock(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, ".X1-lock")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Fatal(err)
	}
	f := Scan(filepath.Join(dir, ".X*-lock"), []int{0}, filepath.Join(dir, "no-proc"))
	if len(f) != 1 || f[0].Severity != report.SeverityMedium {
		t.Errorf("symlinked lock path should be flagged Medium, not read: %+v", f)
	}
}
