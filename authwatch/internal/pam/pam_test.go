package pam

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mtclinton/defensive-suite/authwatch/internal/pkgverify"
	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

func writeSo(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestModules(t *testing.T) {
	dir := t.TempDir()
	writeSo(t, dir, "pam_unix.so")
	writeSo(t, dir, "pam_deny.so")
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if mods := Modules([]string{dir}); len(mods) != 2 {
		t.Errorf("modules=%v", mods)
	}
}

func TestScanFlagsUnownedModule(t *testing.T) {
	dir := t.TempDir()
	owned := writeSo(t, dir, "pam_unix.so")
	evil := writeSo(t, dir, "pam_evil.so")
	f := &runner.Fake{Responses: map[string]runner.Result{
		"rpm -qf " + owned: {Stdout: "pam-1.5\n", ExitCode: 0},
		"rpm -Vf " + owned: {Stdout: "", ExitCode: 0},
		"rpm -qf " + evil:  {Stdout: "file " + evil + " is not owned by any package\n", ExitCode: 1},
	}}
	findings := Scan(context.Background(), f, pkgverify.FamilyRPM, []string{dir})
	unowned := 0
	for _, fd := range findings {
		if fd.Path == evil && fd.Severity == report.SeverityCritical && fd.Technique == "T1556.003" {
			unowned++
		}
		if fd.Path == owned && fd.Severity == report.SeverityCritical {
			t.Error("clean owned module should not be flagged critical")
		}
	}
	if unowned != 1 {
		t.Errorf("want exactly one unowned-critical, got %+v", findings)
	}
}

func TestScanFlagsTamperedOwnedModule(t *testing.T) {
	dir := t.TempDir()
	mod := writeSo(t, dir, "pam_unix.so")
	f := &runner.Fake{Responses: map[string]runner.Result{
		"rpm -qf " + mod: {Stdout: "pam-1.5\n", ExitCode: 0},
		"rpm -Vf " + mod: {Stdout: "..5......  " + mod + "\n", ExitCode: 1},
	}}
	found := false
	for _, fd := range Scan(context.Background(), f, pkgverify.FamilyRPM, []string{dir}) {
		if fd.Path == mod && fd.Severity == report.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("tampered owned module should be flagged critical")
	}
}

func TestScanUnknownFamily(t *testing.T) {
	findings := Scan(context.Background(), &runner.Fake{}, pkgverify.FamilyUnknown, []string{"/x"})
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("findings=%+v", findings)
	}
}
