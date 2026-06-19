package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/config"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/gitleaks"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/honeytoken"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/runner"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/trufflehog"
)

func fixedClock() func() time.Time { return func() time.Time { return time.Unix(0, 0) } }

func TestRunScanTargetsWithBuiltinFallback(t *testing.T) {
	home := t.TempDir()
	// Plant a real-looking AWS credentials file in the fake home.
	mustMkdir(t, filepath.Join(home, ".aws"))
	mustWrite(t, filepath.Join(home, ".aws", "credentials"),
		"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")

	cfg := config.Defaults()
	cfg.HomeDir = home
	cfg.ScanRoots = nil // targets only

	// No tools installed (empty Fake) → built-in fallback must still flag it.
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{Clock: fixedClock()})

	if !hasFinding(rep, "builtinscan", report.SeverityHigh) {
		t.Errorf("built-in fallback did not flag the AWS key with tools absent:\n%+v", rep.Findings)
	}
	if rep.Tool != "credsentinel" {
		t.Errorf("tool=%q", rep.Tool)
	}
}

func TestRunVerifiedTrufflehogHitIsCritical(t *testing.T) {
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, ".aws"))
	credPath := filepath.Join(home, ".aws", "credentials")
	mustWrite(t, credPath, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")

	cfg := config.Defaults()
	cfg.HomeDir = home
	cfg.ScanRoots = nil

	verified := `{"DetectorName":"AWS","Verified":true,"Raw":"AKIA...","SourceMetadata":{"Data":{"Filesystem":{"file":"` + credPath + `"}}}}`
	f := &runner.Fake{Responses: map[string]runner.Result{
		"trufflehog " + strings.Join(trufflehog.Args(credPath), " "): {Stdout: verified + "\n", ExitCode: 183},
	}}
	rep := Run(context.Background(), cfg, f, Options{Clock: fixedClock()})

	if rep.Summary.Worst != report.SeverityCritical || rep.Summary.Clean {
		t.Errorf("a verified-live hit must make the run Critical/non-clean: %+v", rep.Summary)
	}
	if rep.ExitCode() != 2 {
		t.Errorf("exit=%d, want 2", rep.ExitCode())
	}
}

func TestRunCleanHomeIsClean(t *testing.T) {
	home := t.TempDir() // empty home, no credential files
	cfg := config.Defaults()
	cfg.HomeDir = home
	cfg.ScanRoots = nil

	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{Clock: fixedClock()})
	if !rep.Summary.Clean {
		t.Errorf("empty home should scan clean: %+v", rep.Findings)
	}
	if rep.ExitCode() != 0 {
		t.Errorf("exit=%d, want 0", rep.ExitCode())
	}
}

func TestRunScanRootUsesGitleaks(t *testing.T) {
	repo := t.TempDir()
	cfg := config.Defaults()
	cfg.HomeDir = t.TempDir()
	cfg.ScanTargets = false
	cfg.ScanRoots = []string{repo}

	glReport := `[{"Description":"x","File":"` + repo + `/c.tf","RuleID":"aws","StartLine":1,"Secret":"AKIAIOSFODNN7EXAMPLE","Match":"m"}]`
	f := &runner.Fake{Responses: map[string]runner.Result{
		"gitleaks " + strings.Join(gitleaks.Args(repo), " "): {Stdout: glReport, ExitCode: 0},
	}}
	rep := Run(context.Background(), cfg, f, Options{Clock: fixedClock()})
	if !hasFinding(rep, "gitleaks", report.SeverityHigh) {
		t.Errorf("gitleaks finding not surfaced from scan root: %+v", rep.Findings)
	}
}

func TestRunMissingScanRootIsInfo(t *testing.T) {
	cfg := config.Defaults()
	cfg.HomeDir = t.TempDir()
	cfg.ScanTargets = false
	cfg.ScanRoots = []string{"/no/such/dir/credsentinel-test"}

	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{Clock: fixedClock()})
	if !rep.Summary.Clean {
		t.Errorf("a missing scan root should not flip clean: %+v", rep.Findings)
	}
	if !hasFinding(rep, "scan", report.SeverityInfo) {
		t.Errorf("missing root should yield an Info finding: %+v", rep.Findings)
	}
}

func TestRunHoneytokenWatchFolded(t *testing.T) {
	cfg := config.Defaults()
	cfg.HomeDir = t.TempDir()
	cfg.ScanTargets = false
	cfg.ScanRoots = nil
	cfg.ManifestPath = filepath.Join(t.TempDir(), "absent.json")

	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{Clock: fixedClock(), IncludeHoneytokenWatch: true})
	if !hasCheck(rep, "honeytoken") {
		t.Errorf("honeytoken watch not folded into scan: %+v", rep.Findings)
	}
}

// FIX #2: the exposure scan must not read a honeytoken decoy — its in-process read
// would advance the decoy's atime and self-trip the honeytoken watch. A target
// file that is recorded as a decoy in the manifest must be EXCLUDED from the
// targets scan (no per-file targets finding for it).
func TestRunExcludesHoneytokenDecoysFromTargetScan(t *testing.T) {
	home := t.TempDir()
	// A file at a real stealer-target path carrying an AWS key shape.
	mustMkdir(t, filepath.Join(home, ".aws"))
	credPath := filepath.Join(home, ".aws", "credentials")
	mustWrite(t, credPath, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")

	// A manifest that records that path as a deployed decoy.
	manifestPath := filepath.Join(t.TempDir(), "honeytokens.json")
	m := honeytoken.Manifest{
		Tool:   "credsentinel",
		Decoys: []honeytoken.Record{{Name: "aws-credentials-bak", Path: credPath}},
	}
	if err := honeytoken.SaveManifest(manifestPath, m); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.HomeDir = home
	cfg.ScanRoots = nil
	cfg.ManifestPath = manifestPath

	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{Clock: fixedClock()})

	// No targets finding should reference the decoy path — it was excluded.
	for _, f := range rep.Findings {
		if f.Check == "targets" && f.Path == credPath {
			t.Errorf("decoy path was scanned as a target (would self-trip the watch): %+v", f)
		}
	}
	// And the run stays clean: the decoy's AKIA shape must not be flagged because it
	// was never read.
	if !rep.Summary.Clean {
		t.Errorf("excluding the decoy should keep the scan clean: %+v", rep.Findings)
	}
}

// FIX #2 control: without a manifest there is nothing to exclude, so the same
// AKIA-shaped target file IS scanned and flagged — proving the exclusion is
// scoped to actual decoys, not a blanket skip.
func TestRunScansTargetWhenNotADecoy(t *testing.T) {
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, ".aws"))
	mustWrite(t, filepath.Join(home, ".aws", "credentials"),
		"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")

	cfg := config.Defaults()
	cfg.HomeDir = home
	cfg.ScanRoots = nil
	cfg.ManifestPath = filepath.Join(t.TempDir(), "absent.json") // no decoys recorded

	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{Clock: fixedClock()})
	if !hasFinding(rep, "builtinscan", report.SeverityHigh) {
		t.Errorf("a non-decoy AWS key should still be flagged: %+v", rep.Findings)
	}
}

func hasFinding(r report.Report, check string, sev report.Severity) bool {
	for _, f := range r.Findings {
		if f.Check == check && f.Severity == sev {
			return true
		}
	}
	return false
}

func hasCheck(r report.Report, check string) bool {
	for _, f := range r.Findings {
		if f.Check == check {
			return true
		}
	}
	return false
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}
