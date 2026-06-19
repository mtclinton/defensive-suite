// Package scan is the exposure-scanner orchestrator. It runs the configured
// detectors over the scan roots (repos, home) and over the exact stealer target
// files, then assembles a report. A failure in one detector never aborts the
// others — each degrades to a finding, so a missing gitleaks/trufflehog can't
// blind the run; the built-in fallback scanner always covers the stealer targets.
package scan

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/builtinscan"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/config"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/gitleaks"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/honeytoken"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/runner"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/targets"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/trufflehog"
)

// Options tunes a run; Clock is injectable for deterministic tests.
type Options struct {
	Clock func() time.Time
	// IncludeHoneytokenWatch folds the honeytoken watch into the same report (so
	// `credsentinel scan` can give the full DESIGN verdict in one pass). When the
	// manifest is absent it degrades to an informational finding.
	IncludeHoneytokenWatch bool
}

// Run executes the exposure scan and returns the assembled report. r drives
// gitleaks/trufflehog; the built-in scanner runs in-process on the stealer
// targets regardless of whether those tools are present.
func Run(ctx context.Context, cfg config.Config, r runner.Runner, opts Options) report.Report {
	clock := time.Now
	if opts.Clock != nil {
		clock = opts.Clock
	}
	host, _ := os.Hostname()

	var findings []report.Finding

	// The honeytoken decoys live in the home dir exactly where a stealer looks, so
	// the exposure scan would otherwise read them — and credsentinel's own read
	// advances a decoy's atime, which is precisely the honeytoken trip signal. That
	// would make the scan service self-trip a false "decoy was read" on every run.
	// Build the decoy-path set once and exclude those paths from every leg of the
	// exposure scan below.
	decoys := decoyPaths(cfg)

	// (1) Scan roots (repos, home) with gitleaks + trufflehog.
	for _, root := range cfg.ScanRoots {
		dir := cfg.ExpandHome(root)
		if _, err := os.Stat(dir); err != nil {
			findings = append(findings, report.Finding{
				Check: "scan", Severity: report.SeverityInfo, Path: dir,
				Title: "configured scan root does not exist; skipped",
			})
			continue
		}
		findings = append(findings, gitleaks.Scan(ctx, r, dir)...)
		findings = append(findings, trufflehog.Scan(ctx, r, dir)...)
	}

	// (2) Exact stealer target files: trufflehog (liveness) + built-in fallback
	// per file, so the highest-value paths are always covered even with no tools.
	if cfg.ScanTargets {
		findings = append(findings, scanTargets(ctx, cfg, r, decoys)...)
	}

	// (3) Optional honeytoken watch folded into the same report.
	if opts.IncludeHoneytokenWatch {
		findings = append(findings, watchHoneytokens(cfg)...)
	}

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			Check: "scan", Severity: report.SeverityInfo,
			Title: "nothing configured to scan (no roots, targets disabled)",
		})
	}
	return report.New("credsentinel", host, "", clock(), findings)
}

// scanTargets resolves the stealer target files under home and scans each with
// trufflehog (verified-live) and the built-in fallback. A present-but-clean
// target still yields an Info finding so the report shows what was covered.
// decoys is the set of honeytoken decoy paths to exclude: reading a decoy here
// would advance its atime and self-trip the honeytoken watch.
func scanTargets(ctx context.Context, cfg config.Config, r runner.Runner, decoys map[string]bool) []report.Finding {
	home := cfg.Home()
	hits := targets.Resolve(home, targets.StealerTargets)
	if len(hits) == 0 {
		return []report.Finding{{
			Check: "targets", Severity: report.SeverityInfo,
			Title: "no stealer-target credential files present in home",
		}}
	}
	var findings []report.Finding
	for _, h := range hits {
		// Never read a honeytoken decoy: that read would advance its atime and the
		// honeytoken watch would then fire a false "decoy was read" trip.
		if decoys[h.Path] {
			continue
		}
		// trufflehog verifies liveness on the single file.
		findings = append(findings, trufflehog.Scan(ctx, r, h.Path)...)
		// Built-in fallback always runs in-process — the guaranteed coverage.
		data, err := readLimited(h.Path, cfg.MaxFileBytes)
		if err != nil {
			findings = append(findings, report.Finding{
				Check: "targets", Severity: report.SeverityLow, Path: h.Path,
				Title: "stealer-target file present but unreadable", Detail: err.Error(),
			})
			continue
		}
		ms := builtinscan.ScanText(string(data))
		if len(ms) == 0 {
			findings = append(findings, report.Finding{
				Check: "targets", Severity: report.SeverityInfo, Path: h.Path,
				Title: "stealer-target present; no secret shape matched (" + h.Kind + ")",
			})
			continue
		}
		findings = append(findings, builtinscan.FindingsFor(h.Path, h.Kind, ms)...)
	}
	return findings
}

// decoyPaths loads the honeytoken manifest (if present) and returns the set of
// deployed decoy file paths so the exposure scan can avoid reading them. A
// missing/unreadable manifest yields an empty set — the scan simply has nothing
// to exclude. This read is bounded inside honeytoken.LoadManifest.
func decoyPaths(cfg config.Config) map[string]bool {
	set := map[string]bool{}
	m, err := honeytoken.LoadManifest(cfg.ExpandHome(cfg.ManifestPath))
	if err != nil {
		return set
	}
	for _, rec := range m.Decoys {
		set[rec.Path] = true
	}
	return set
}

func watchHoneytokens(cfg config.Config) []report.Finding {
	mp := cfg.ExpandHome(cfg.ManifestPath)
	m, err := honeytoken.LoadManifest(mp)
	if err != nil {
		return []report.Finding{{
			Check: "honeytoken", Severity: report.SeverityInfo, Path: mp,
			Title: "no honeytoken manifest; run `credsentinel deploy` to plant decoys",
		}}
	}
	findings := honeytoken.Watch(m)
	findings = append(findings, honeytoken.SummaryFinding(m, findings))
	return findings
}

// readLimited reads at most maxBytes from path. A stealer target lives in a
// user-writable home, so an attacker could point it at an endless file (a symlink
// to /dev/zero); the bound keeps the scanner from OOMing.
func readLimited(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
