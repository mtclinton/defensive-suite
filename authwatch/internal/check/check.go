// Package check runs every authwatch check in sequence and assembles the
// Report. A failure in one check never aborts the others — each degrades to a
// finding so a single missing tool can't blind the whole run.
package check

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mtclinton/defensive-suite/authwatch/internal/aide"
	"github.com/mtclinton/defensive-suite/authwatch/internal/auditd"
	"github.com/mtclinton/defensive-suite/authwatch/internal/authkeys"
	"github.com/mtclinton/defensive-suite/authwatch/internal/baseline"
	"github.com/mtclinton/defensive-suite/authwatch/internal/config"
	"github.com/mtclinton/defensive-suite/authwatch/internal/pam"
	"github.com/mtclinton/defensive-suite/authwatch/internal/pkgverify"
	"github.com/mtclinton/defensive-suite/authwatch/internal/preload"
	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
	"github.com/mtclinton/defensive-suite/authwatch/internal/x11lock"
)

const ldSoPreloadPath = "/etc/ld.so.preload"

// Options tunes a run. Clock and ProcDir are injectable for testing.
type Options struct {
	RunAIDE bool
	Clock   func() time.Time
	ProcDir string
}

// DetectFamily reads /etc/os-release to determine the package-manager family.
func DetectFamily() pkgverify.Family {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return pkgverify.FamilyUnknown
	}
	return pkgverify.DetectFamily(string(b))
}

// AuthCriticalPaths is the set the baseline and hash diff cover: the configured
// auth binaries plus every PAM module currently on disk.
func AuthCriticalPaths(cfg config.Config) []string {
	paths := append([]string{}, cfg.AuthBinaries...)
	return append(paths, pam.Modules(cfg.SecurityDirs)...)
}

// Run executes all checks and returns the assembled report.
func Run(ctx context.Context, cfg config.Config, r runner.Runner, opts Options) report.Report {
	clock := time.Now
	if opts.Clock != nil {
		clock = opts.Clock
	}
	procDir := opts.ProcDir
	if procDir == "" {
		procDir = "/proc"
	}
	host, _ := os.Hostname()
	fam := DetectFamily()

	var findings []report.Finding
	findings = append(findings, pkgverify.Verify(ctx, r, fam, cfg.AuthBinaries)...)
	findings = append(findings, pam.Scan(ctx, r, fam, cfg.SecurityDirs)...)
	findings = append(findings, baselineDiff(cfg)...)
	findings = append(findings, authkeysScan(cfg)...)
	findings = append(findings, preload.Scan(ldSoPreloadPath, cfg.ShellInit, cfg.SystemdDirs)...)
	findings = append(findings, x11lock.Scan(cfg.XLockGlob, cfg.XServerUIDs, procDir)...)
	findings = append(findings, auditd.Check(ctx, r)...)
	if opts.RunAIDE {
		findings = append(findings, aide.Run(ctx, r, cfg.AIDEConfig)...)
	}

	return report.New("authwatch", host, fam.String(), clock(), findings)
}

func baselineDiff(cfg config.Config) []report.Finding {
	if cfg.BaselinePath == "" {
		return []report.Finding{{
			Check: "baseline", Severity: report.SeverityInfo,
			Title: "no baseline path configured; off-host hash diff skipped",
		}}
	}
	b, err := baseline.Load(cfg.BaselinePath)
	if err != nil {
		return []report.Finding{{
			Check: "baseline", Severity: report.SeverityLow,
			Title: "could not load off-host baseline", Detail: err.Error(),
		}}
	}
	return baseline.Diff(b, AuthCriticalPaths(cfg))
}

func authkeysScan(cfg config.Config) []report.Finding {
	allow, err := authkeys.LoadAllowlist(cfg.AllowlistPath)
	if err != nil {
		return []report.Finding{{
			Check: "authkeys", Severity: report.SeverityLow,
			Title: "could not load authorized_keys allowlist", Detail: err.Error(),
		}}
	}
	configured := cfg.AllowlistPath != ""
	var findings []report.Finding
	if !configured {
		findings = append(findings, report.Finding{
			Check: "authkeys", Severity: report.SeverityInfo,
			Title: "no authorized_keys allowlist configured; keys reported but not judged",
		})
	}
	for _, glob := range cfg.SSHKeyGlobs {
		matches, err := filepath.Glob(glob)
		if err != nil {
			continue
		}
		for _, p := range matches {
			data, err := readLimited(p, 1<<20)
			if err != nil {
				continue
			}
			content := string(data)
			if configured {
				findings = append(findings, authkeys.Audit(p, content, allow)...)
				continue
			}
			for _, k := range authkeys.ParseAuthorizedKeys(content) {
				findings = append(findings, report.Finding{
					Check: "authkeys", Severity: report.SeverityInfo, Path: p,
					Title:  "authorized_keys entry (unjudged; no allowlist)",
					Detail: fmt.Sprintf("type=%s fp=%s comment=%q", k.Type, k.Fingerprint, k.Comment),
				})
			}
		}
	}
	return findings
}

// readLimited reads at most maxBytes from path. authorized_keys lives in a
// user-writable home directory, so an attacker could point it at an endless file
// (e.g. a symlink to /dev/zero); the bound keeps this root process from OOMing.
func readLimited(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
