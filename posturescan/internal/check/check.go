// Package check runs every posturescan check in sequence and assembles the
// Report, including the per-sysctl OK/DIFFERENT table and the hardening index.
// A failure in one check never aborts the others — each degrades to a finding so
// a single missing tool can't blind the whole run.
package check

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/mtclinton/defensive-suite/posturescan/internal/caps"
	"github.com/mtclinton/defensive-suite/posturescan/internal/config"
	"github.com/mtclinton/defensive-suite/posturescan/internal/podman"
	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
	"github.com/mtclinton/defensive-suite/posturescan/internal/runner"
	"github.com/mtclinton/defensive-suite/posturescan/internal/sysctl"
	"github.com/mtclinton/defensive-suite/posturescan/internal/tools"
)

// Options tunes a run. Clock is injectable for deterministic tests; WrapTools
// gates the lynis/oscap/systemd-analyze wrappers (off by default to keep a scan
// fast and self-contained).
type Options struct {
	Clock     func() time.Time
	WrapTools bool
}

// DetectDistro reads /etc/os-release ID for the report's Distro field.
func DetectDistro() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.TrimSpace(k) == "ID" {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// Targets returns the effective sysctl targets for cfg: the goal profile,
// overlaid with cfg.ProfilePath when set. A profile that fails to load degrades
// to the built-in goal profile (the load error is not fatal to a scan).
func Targets(cfg config.Config) []sysctl.Target {
	targets, err := sysctl.LoadProfile(cfg.ProfilePath)
	if err != nil {
		return sysctl.GoalProfile()
	}
	return targets
}

// SysctlRows reads the host's sysctls (proc-sys root first, then `sysctl -a`
// fallback via the runner) plus the lockdown state, and diffs them against the
// targets. Returned separately from Run so `remediate` can reuse it.
func SysctlRows(ctx context.Context, cfg config.Config, r runner.Runner, targets []sysctl.Target) ([]report.SysctlRow, []report.Finding) {
	src := sysctlSource(ctx, cfg, r)
	rows := sysctl.Diff(targets, src)
	findings := sysctl.Findings(targets, rows)

	// Lockdown lives outside /proc/sys; read it from its securityfs file.
	mode, supported := readLockdown(cfg.LockdownPath)
	lockRow, lockFinding, reported := sysctl.EvaluateLockdown(mode, supported)
	rows = append(rows, lockRow)
	if reported {
		findings = append(findings, lockFinding)
	}
	return rows, findings
}

// sysctlSource builds the value source: the proc-sys directory, with parsed
// `sysctl -a` output as a fallback for keys not present as files (e.g.
// module.sig_enforce, which sysctl surfaces but /proc/sys does not expose).
func sysctlSource(ctx context.Context, cfg config.Config, r runner.Runner) sysctl.Source {
	procSrc := sysctl.NewProcSysSource(cfg.ProcSysRoot)
	res, err := r.Run(ctx, "sysctl", "-a")
	if err != nil {
		return procSrc // runner/tool absent — proc-sys only
	}
	return sysctl.Chain(procSrc, sysctl.NewMapSource(sysctl.ParseSysctlA(res.Stdout)))
}

func readLockdown(path string) (mode string, supported bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return sysctl.ParseLockdown(string(b)), true
}

// Run executes all checks and returns the assembled report with its Posture.
func Run(ctx context.Context, cfg config.Config, r runner.Runner, opts Options) report.Report {
	clock := time.Now
	if opts.Clock != nil {
		clock = opts.Clock
	}
	host, _ := os.Hostname()
	distro := DetectDistro()
	targets := Targets(cfg)

	var findings []report.Finding

	// 1. Sysctls + lockdown (the OK/DIFFERENT table + hardening index).
	rows, sysctlFindings := SysctlRows(ctx, cfg, r, targets)
	findings = append(findings, sysctlFindings...)

	// 2. Capabilities audit: systemd units + container specs.
	findings = append(findings, caps.AuditUnitDirs(cfg.SystemdDirs, cfg.LegitBPFTools)...)
	containerFindings, specs := caps.AuditContainerSpecs(cfg.ContainerSpecs, cfg.LegitBPFTools)
	findings = append(findings, containerFindings...)

	// 3. Podman posture score per container spec.
	for _, s := range specs {
		findings = append(findings, podmanScore(s)...)
	}

	// 4. Tool wrappers (opt-in).
	if opts.WrapTools {
		findings = append(findings, tools.Lynis(ctx, r)...)
		findings = append(findings, tools.Oscap(ctx, r, cfg.OscapDatastream, cfg.OscapProfile)...)
		findings = append(findings, tools.SystemdSecurity(ctx, r)...)
	}

	rep := report.New("posturescan", host, distro, clock(), findings)
	rep.Posture = &report.Posture{
		HardeningIndex: sysctl.HardeningIndex(rows),
		TargetIndex:    100,
		Sysctls:        rows,
	}
	return rep
}

func podmanScore(s podman.Spec) []report.Finding {
	return s.Findings()
}
