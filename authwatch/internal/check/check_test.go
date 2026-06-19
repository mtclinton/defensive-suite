package check

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/authwatch/internal/config"
	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

func TestAuthCriticalPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pam_unix.so"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.AuthBinaries = []string{"/usr/sbin/sshd"}
	cfg.SecurityDirs = []string{dir}
	if paths := AuthCriticalPaths(cfg); len(paths) != 2 {
		t.Errorf("paths=%v", paths)
	}
}

func TestRunProducesReport(t *testing.T) {
	cfg := config.Defaults()
	cfg.SecurityDirs = []string{t.TempDir()}
	cfg.AuthBinaries = nil
	cfg.SSHKeyGlobs = nil
	cfg.ShellInit = nil
	cfg.SystemdDirs = nil
	cfg.XLockGlob = filepath.Join(t.TempDir(), ".X*-lock")

	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{
		Clock:   func() time.Time { return fixed },
		ProcDir: t.TempDir(),
	})
	if rep.Tool != "authwatch" {
		t.Errorf("tool=%s", rep.Tool)
	}
	if !rep.Time.Equal(fixed) {
		t.Errorf("injected clock not used: %v", rep.Time)
	}
	if rep.Findings == nil {
		t.Error("findings should be non-nil")
	}
}

func TestAuthkeysScanModes(t *testing.T) {
	dir := t.TempDir()
	ak := filepath.Join(dir, "authorized_keys")
	blob := base64.StdEncoding.EncodeToString([]byte("attacker-key-blob-1"))
	if err := os.WriteFile(ak, []byte("ssh-ed25519 "+blob+" attacker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.SSHKeyGlobs = []string{ak}

	// Unconfigured allowlist: a "no allowlist" Info plus a per-key unjudged Info.
	cfg.AllowlistPath = ""
	infos := 0
	for _, f := range authkeysScan(cfg) {
		if f.Severity == report.SeverityInfo {
			infos++
		}
	}
	if infos < 2 {
		t.Errorf("unconfigured allowlist: want >=2 Info findings, got %d", infos)
	}

	// Configured allowlist that omits the key: one High T1098.004.
	al := filepath.Join(dir, "allow")
	if err := os.WriteFile(al, []byte("# no trusted keys\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.AllowlistPath = al
	high := 0
	for _, f := range authkeysScan(cfg) {
		if f.Severity == report.SeverityHigh && f.Technique == "T1098.004" {
			high++
		}
	}
	if high != 1 {
		t.Errorf("configured allowlist omitting the key: want 1 High T1098.004, got %d", high)
	}
}
