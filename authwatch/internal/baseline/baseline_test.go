package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHashFileKnownVector(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "f", "hello")
	e, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if e.Size != 5 {
		t.Errorf("size=%d", e.Size)
	}
	const wantHello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if e.SHA256 != wantHello {
		t.Errorf("sha256=%s want %s", e.SHA256, wantHello)
	}
}

func TestCaptureSaveLoadDiffClean(t *testing.T) {
	dir := t.TempDir()
	p1 := write(t, dir, "sshd", "good")
	p2 := write(t, dir, "ssh", "good2")
	base := Capture("h", time.Unix(0, 0), []string{p1, p2})
	bp := filepath.Join(dir, "baseline.json")
	if err := base.Save(bp); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(bp)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Entries) != 2 {
		t.Fatalf("entries=%d", len(loaded.Entries))
	}
	if f := Diff(loaded, []string{p1, p2}); len(f) != 0 {
		t.Errorf("unchanged files should diff clean, got %+v", f)
	}
}

func TestDiffDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "sshd", "good")
	base := Capture("h", time.Unix(0, 0), []string{p})
	write(t, dir, "sshd", "EVIL") // overwrite
	f := Diff(base, []string{p})
	if len(f) != 1 || f[0].Severity != report.SeverityCritical || f[0].Technique != "T1554" {
		t.Errorf("tamper diff=%+v", f)
	}
}

func TestDiffMissingAndUnbaselined(t *testing.T) {
	dir := t.TempDir()
	p1 := write(t, dir, "a", "x")
	base := Capture("h", time.Unix(0, 0), []string{p1})
	if err := os.Remove(p1); err != nil {
		t.Fatal(err)
	}
	p2 := write(t, dir, "b", "y") // present but not baselined
	high, low := 0, 0
	for _, fd := range Diff(base, []string{p1, p2}) {
		switch fd.Severity {
		case report.SeverityHigh:
			high++
		case report.SeverityLow:
			low++
		}
	}
	if high != 1 || low != 1 {
		t.Errorf("expected one high (missing) + one low (unbaselined), got high=%d low=%d", high, low)
	}
}

func TestDiffEmptyBaselineIsInfo(t *testing.T) {
	f := Diff(Baseline{Entries: map[string]Entry{}}, []string{"/x"})
	if len(f) != 1 || f[0].Severity != report.SeverityInfo {
		t.Errorf("empty baseline diff=%+v", f)
	}
}

func TestDiffDetectsDroppedBaselinedPath(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "pam_unix.so", "good")
	base := Capture("h", time.Unix(0, 0), []string{p})
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	// The deleted module is no longer in the scanned path set (nil), yet its
	// disappearance must still be caught via the baseline's own keys.
	f := Diff(base, nil)
	if len(f) != 1 || f[0].Severity != report.SeverityHigh || f[0].Path != p {
		t.Errorf("dropped baselined path should be flagged High missing: %+v", f)
	}
}
