package preload

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
)

func TestScanLdSoPreload(t *testing.T) {
	if f := ScanLdSoPreload("/etc/ld.so.preload", "# only a comment\n\n"); len(f) != 0 {
		t.Errorf("comment/blank-only should be clean: %+v", f)
	}
	f := ScanLdSoPreload("/etc/ld.so.preload", "/tmp/evil.so\n")
	if len(f) != 1 || f[0].Severity != report.SeverityCritical || f[0].Technique != "T1574.006" {
		t.Errorf("populated=%+v", f)
	}
	if f[0].Sigma != "lnx_auditd_ld_so_preload_mod" {
		t.Errorf("sigma=%s", f[0].Sigma)
	}
}

func TestScanShellInit(t *testing.T) {
	clean := "export PATH=/usr/bin\n# LD_PRELOAD=/x in a comment\nunset LD_PRELOAD\n"
	if f := ScanShellInit("/etc/profile", clean); len(f) != 0 {
		t.Errorf("clean shell init flagged: %+v", f)
	}
	f := ScanShellInit("/root/.bashrc", "export LD_PRELOAD=/tmp/x.so")
	if len(f) != 1 || f[0].Severity != report.SeverityHigh {
		t.Errorf("LD_PRELOAD assignment not flagged: %+v", f)
	}
}

func TestScanSystemdUnit(t *testing.T) {
	clean := "[Service]\nExecStart=/bin/true\nEnvironment=FOO=bar\n"
	if f := ScanSystemdUnit("/x.service", clean); len(f) != 0 {
		t.Errorf("clean unit flagged: %+v", f)
	}
	f := ScanSystemdUnit("/x.service", "[Service]\nEnvironment=LD_PRELOAD=/tmp/x.so\n")
	if len(f) != 1 || f[0].Severity != report.SeverityHigh {
		t.Errorf("unit LD_PRELOAD not flagged: %+v", f)
	}
}

func TestScanIntegration(t *testing.T) {
	dir := t.TempDir()
	ld := filepath.Join(dir, "ld.so.preload")
	mustWrite(t, ld, "/tmp/evil.so\n")
	bashrc := filepath.Join(dir, "bashrc")
	mustWrite(t, bashrc, "export LD_PRELOAD=/x.so\n")
	unitDir := filepath.Join(dir, "system")
	if err := os.Mkdir(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(unitDir, "evil.service"), "[Service]\nEnvironment=LD_PRELOAD=/x.so\n")

	f := Scan(ld, []string{bashrc}, []string{unitDir})
	if len(f) != 3 {
		t.Errorf("expected ld + shell + unit findings, got %d: %+v", len(f), f)
	}
}

func TestScanAbsentLdSoPreloadIsClean(t *testing.T) {
	if f := Scan(filepath.Join(t.TempDir(), "absent"), nil, nil); len(f) != 0 {
		t.Errorf("absent ld.so.preload (the clean state) should yield nothing: %+v", f)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
