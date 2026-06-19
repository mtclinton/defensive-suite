package auditlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

func TestParseLogVerboseLifecycle(t *testing.T) {
	log := `0 verbose cli /usr/bin/node
12 verbose lifecycle poisoned-pkg@1.2.3~postinstall: PATH: /node_modules/.bin
13 info run lodash@4.17.21 install node_modules/lodash node-gyp rebuild
14 silly something unrelated`
	events := ParseLog(log)
	if len(events) == 0 {
		t.Fatal("expected lifecycle events")
	}
	foundPostinstall := false
	foundInstall := false
	for _, e := range events {
		if e.Package == "poisoned-pkg" && e.Script == "postinstall" {
			foundPostinstall = true
		}
		if e.Package == "lodash" && e.Script == "install" {
			foundInstall = true
		}
	}
	if !foundPostinstall {
		t.Errorf("missed poisoned-pkg postinstall in %+v", events)
	}
	if !foundInstall {
		t.Errorf("missed lodash install in %+v", events)
	}
}

func TestParseLogDeduplicates(t *testing.T) {
	log := `1 verbose lifecycle a@1~postinstall: x
2 verbose lifecycle a@1~postinstall: y`
	if events := ParseLog(log); len(events) != 1 {
		t.Errorf("expected dedup to 1 event, got %+v", events)
	}
}

func TestParseLogFallbackKeyword(t *testing.T) {
	log := `99 verbose lifecycle running postinstall now`
	events := ParseLog(log)
	if len(events) == 0 {
		t.Fatalf("fallback should catch a bare lifecycle keyword")
	}
}

func TestParseLogIgnoresProse(t *testing.T) {
	// A line that mentions "postinstall" but is not a lifecycle line.
	log := `0 verbose cli checking the postinstall documentation`
	if events := ParseLog(log); len(events) != 0 {
		t.Errorf("prose mention should not be an event: %+v", events)
	}
}

func TestFindingsSeverity(t *testing.T) {
	f := Findings("/logs/x.log", []Event{{Package: "evil", Script: "postinstall"}})
	if len(f) != 1 || f[0].Severity != report.SeverityMedium {
		t.Errorf("postinstall finding=%+v", f)
	}
	if f[0].Package != "evil" {
		t.Errorf("package not tagged: %+v", f[0])
	}
}

func TestScanDirectory(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "2026-06-19T00_debug.log"),
		"5 verbose lifecycle malware@9.9.9~postinstall: PATH=x")
	mustWrite(t, filepath.Join(dir, "notalog.txt"), "ignored")
	findings, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, f := range findings {
		if f.Package == "malware" && f.Severity == report.SeverityMedium {
			hit = true
		}
	}
	if !hit {
		t.Errorf("scan missed the postinstall: %+v", findings)
	}
}

// Fix #5: an oversize log (install scripts can write into ~/.npm/_logs) is read
// under a bound — it must not be loaded whole — yet the lifecycle events in the
// leading content are still surfaced. The read is capped at maxLogBytes.
func TestScanBoundsOversizeLog(t *testing.T) {
	dir := t.TempDir()
	var sb strings.Builder
	// A real lifecycle event up front, then megabytes of padding past the cap.
	sb.WriteString("5 verbose lifecycle bigpkg@1.0.0~postinstall: PATH=x\n")
	pad := strings.Repeat("x", 1024)
	for sb.Len() < maxLogBytes+(1<<20) {
		sb.WriteString(pad)
		sb.WriteByte('\n')
	}
	mustWrite(t, filepath.Join(dir, "huge.log"), sb.String())

	findings, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, f := range findings {
		if f.Package == "bigpkg" && f.Severity == report.SeverityMedium {
			hit = true
		}
	}
	if !hit {
		t.Errorf("leading lifecycle event should survive the bounded read: %+v", findings)
	}
}

// readLogBounded must cap the bytes it returns at the limit.
func TestReadLogBoundedCaps(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.log")
	mustWrite(t, p, strings.Repeat("z", 100))
	b, err := readLogBounded(p, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 10 {
		t.Errorf("bounded read returned %d bytes, want 10", len(b))
	}
}

func TestScanMissingDirIsInfo(t *testing.T) {
	findings, err := Scan(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("missing dir should be a single info: %+v", findings)
	}
}

func TestScanEmptyDirIsInfo(t *testing.T) {
	findings, err := Scan(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("empty dir should be a single info: %+v", findings)
	}
}

func TestDefaultLogsDirOverride(t *testing.T) {
	if got := DefaultLogsDir("/custom/logs"); got != "/custom/logs" {
		t.Errorf("override ignored: %q", got)
	}
	if got := DefaultLogsDir(""); got == "" {
		t.Error("default logs dir should not be empty")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
