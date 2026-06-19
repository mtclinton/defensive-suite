// Package check runs every instguard check in sequence and assembles the
// Report plus the per-package verdicts. A failure in one check never aborts the
// others — each degrades to a finding so a single missing tool or no-network
// condition can't blind the whole run (the npm binary being absent is an Info
// "tool absent", never a crash; OSV with no network is an Info skip).
package check

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/mtclinton/defensive-suite/instguard/internal/aur"
	"github.com/mtclinton/defensive-suite/instguard/internal/config"
	"github.com/mtclinton/defensive-suite/instguard/internal/cooldown"
	"github.com/mtclinton/defensive-suite/instguard/internal/hooks"
	"github.com/mtclinton/defensive-suite/instguard/internal/lockfile"
	"github.com/mtclinton/defensive-suite/instguard/internal/osv"
	"github.com/mtclinton/defensive-suite/instguard/internal/report"
	"github.com/mtclinton/defensive-suite/instguard/internal/runner"
	"github.com/mtclinton/defensive-suite/instguard/internal/verdict"
)

// Options tunes a run. Clock, HTTP, and ReleaseDates are injectable for testing
// and for offline operation.
type Options struct {
	// Clock supplies "now" for the release-age cooldown; defaults to time.Now.
	Clock func() time.Time
	// HTTP is the OSV query transport. Nil means offline (OSV gracefully skipped).
	HTTP osv.Doer
	// ReleaseDates maps "name@version" to a registry publish timestamp for the
	// cooldown check. Absent entries simply skip the cooldown for that package —
	// the comparison stays a pure, injected-input function.
	ReleaseDates map[string]time.Time
}

// Run executes all pre-install checks against the configured project and returns
// the assembled report (findings + per-package verdicts).
func Run(ctx context.Context, cfg config.Config, r runner.Runner, opts Options) report.Report {
	clock := time.Now
	if opts.Clock != nil {
		clock = opts.Clock
	}
	host, _ := os.Hostname()

	var findings []report.Finding

	// 1. Lockfile drift + competing lockfiles. Reuses the parsed manifest below.
	lock, err := lockfile.Scan(cfg.ProjectDir)
	if err != nil {
		findings = append(findings, report.Finding{
			Check: "lockfile", Severity: report.SeverityLow,
			Title: "could not read project files", Detail: err.Error(),
		})
	}
	findings = append(findings, lock.Findings...)

	// 2. Install-hook scanner over the project's own package.json scripts.
	if lock.ManifestFound {
		findings = append(findings, hooks.ScanScripts(lock.Manifest.Name, lock.Manifest.Scripts)...)
		for _, name := range hooks.InstallScriptNames(lock.Manifest.Scripts) {
			findings = append(findings, report.Finding{
				Check: "hooks", Severity: report.SeverityInfo, Package: lock.Manifest.Name,
				Title:  "install lifecycle script present (" + name + ")",
				Detail: "runs arbitrary code at install time; prefer `npm ci --ignore-scripts` then a vetted second pass",
			})
		}
	}

	// 3. OSV.dev query for each pinned (package, version).
	findings = append(findings, osvCheck(ctx, cfg, opts, lock.Locked)...)

	// 4. Release-age cooldown over pinned versions with a known publish date.
	findings = append(findings, cooldownCheck(cfg, opts, clock(), lock.Locked)...)

	// 5. AUR build-file scan (PKGBUILD / .install / .hook).
	findings = append(findings, aurCheck(cfg)...)

	// npm presence is informational only — degrade gracefully when absent.
	findings = append(findings, npmPresence(ctx, r)...)

	verdicts := verdict.Build(findings, lock.Locked)
	return report.New("instguard", host, "", clock(), findings, verdicts)
}

func osvCheck(ctx context.Context, cfg config.Config, opts Options, locked map[string][]string) []report.Finding {
	if cfg.OfflineOSV || opts.HTTP == nil {
		return []report.Finding{{
			Check: "osv", Severity: report.SeverityInfo,
			Title: "OSV query skipped (offline); pinned versions not checked against MAL- advisories",
		}}
	}
	client := osv.Client{URL: cfg.OSVQueryURL, HTTP: opts.HTTP}
	var findings []report.Finding
	// Query EVERY distinct (name, version): two copies of the same package at
	// different paths are both installed, so a poisoned nested copy must not be
	// skipped just because another version of that name was also resolved.
	for _, name := range sortedKeys(locked) {
		for _, version := range locked[name] {
			if version == "" {
				continue
			}
			vulns, err := client.Query(ctx, name, version)
			if err != nil {
				findings = append(findings, report.Finding{
					Check: "osv", Severity: report.SeverityLow, Package: name,
					Title: "OSV query failed; could not check this version", Detail: err.Error(),
				})
				continue
			}
			findings = append(findings, osv.Findings(name, version, vulns)...)
		}
	}
	return findings
}

func cooldownCheck(cfg config.Config, opts Options, now time.Time, locked map[string][]string) []report.Finding {
	if cfg.CooldownDays <= 0 || len(opts.ReleaseDates) == 0 {
		return nil
	}
	var releases []cooldown.Release
	// Every distinct version gets its own cooldown check — a freshly published
	// nested copy must be flagged even when an older copy of the same name exists.
	for _, name := range sortedKeys(locked) {
		for _, version := range locked[name] {
			if published, ok := opts.ReleaseDates[name+"@"+version]; ok {
				releases = append(releases, cooldown.Release{Package: name, Version: version, PublishedAt: published})
			}
		}
	}
	return cooldown.CheckAll(releases, now, cfg.CooldownDays)
}

func aurCheck(cfg config.Config) []report.Finding {
	var findings []report.Finding
	for _, pat := range cfg.AURPaths {
		glob := pat
		if !filepath.IsAbs(glob) {
			glob = filepath.Join(cfg.ProjectDir, pat)
		}
		matches, err := filepath.Glob(glob)
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, p := range matches {
			b, err := readLimited(p, 1<<20)
			if err != nil {
				continue
			}
			findings = append(findings, aur.ScanFile(p, string(b))...)
		}
	}
	return findings
}

func npmPresence(ctx context.Context, r runner.Runner) []report.Finding {
	res, err := r.Run(ctx, "npm", "--version")
	if err != nil {
		return []report.Finding{{
			Check: "npm", Severity: report.SeverityInfo,
			Title: "npm not found on PATH; static analysis ran, npm-assisted checks skipped",
		}}
	}
	return []report.Finding{{
		Check: "npm", Severity: report.SeverityInfo,
		Title:  "npm present",
		Detail: "version " + trimSpace(res.Stdout),
	}}
}

// DefaultHTTPClient is the production OSV transport: a short timeout so a slow or
// unreachable OSV endpoint degrades to a per-package Low rather than hanging.
func DefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func readLimited(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	var total int64
	for total < maxBytes {
		n, err := f.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
