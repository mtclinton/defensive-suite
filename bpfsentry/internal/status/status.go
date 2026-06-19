// Package status reports bpfsentry's own detection-coverage posture: which of
// the three design layers are actually live on this host. It answers "can we
// even see a rootkit if one is here?" — reduced visibility is itself a finding,
// because a clean run from a blind tool is worthless.
package status

import (
	"context"
	"os"

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/enumerate"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/report"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/runner"
)

// Options injects the seams the status check needs so it stays unit-testable:
// the path probe and the live enumeration both come in as functions.
type Options struct {
	// BPFToolPath is the configured bpftool; a probe checks it is runnable.
	BPFToolPath string
	// BaselinePath is the configured early-boot allowlist path; "" means none.
	BaselinePath string
	// BaselineExists reports whether the baseline file is present. Injectable for
	// tests; defaults to os.Stat.
	BaselineExists func(path string) bool
	// Enumerate runs the live portable enumeration. Injectable for tests;
	// defaults to enumerate.Enumerate via the runner.
	Enumerate func(ctx context.Context) (enumerate.Inventory, error)
}

// Check assembles the visibility-posture findings.
func Check(ctx context.Context, r runner.Runner, opts Options) []report.Finding {
	existsFn := opts.BaselineExists
	if existsFn == nil {
		existsFn = func(p string) bool {
			if p == "" {
				return false
			}
			_, err := os.Stat(p)
			return err == nil
		}
	}
	enumFn := opts.Enumerate
	if enumFn == nil {
		enumFn = func(ctx context.Context) (enumerate.Inventory, error) {
			return enumerate.Enumerate(ctx, r, opts.BPFToolPath)
		}
	}

	var findings []report.Finding

	// Layer 1: early-boot allowlist present?
	if opts.BaselinePath == "" {
		findings = append(findings, report.Finding{
			Check: "status", Severity: report.SeverityLow,
			Title: "no early-boot allowlist configured; the diff path is blind",
		})
	} else if !existsFn(opts.BaselinePath) {
		findings = append(findings, report.Finding{
			Check: "status", Severity: report.SeverityLow,
			Title: "configured early-boot allowlist is missing on disk", Path: opts.BaselinePath,
		})
	} else {
		findings = append(findings, report.Finding{
			Check: "status", Severity: report.SeverityInfo,
			Title: "early-boot allowlist present", Path: opts.BaselinePath,
		})
	}

	// Live enumeration (portable path) reachable?
	inv, err := enumFn(ctx)
	if err != nil {
		findings = append(findings, report.Finding{
			Check: "status", Severity: report.SeverityLow,
			Title:  "live BPF enumeration unavailable (bpftool); reduced visibility",
			Detail: err.Error(), Technique: "T1562.001",
		})
	} else {
		findings = append(findings, report.Finding{
			Check: "status", Severity: report.SeverityInfo,
			Title:  "live BPF enumeration available",
			Detail: countDetail(inv),
		})
	}

	// Layer 3 reminder: the out-of-band path is the only one that cannot be
	// lied to. It runs off-host (forensics/), so status can only remind.
	findings = append(findings, report.Finding{
		Check: "status", Severity: report.SeverityInfo,
		Title: "out-of-band memory forensics is the only un-lie-able path; run forensics/ off-host on the latest snapshot",
	})

	return findings
}

func countDetail(inv enumerate.Inventory) string {
	return "programs=" + itoa(len(inv.Programs)) +
		" maps=" + itoa(len(inv.Maps)) +
		" links=" + itoa(len(inv.Links))
}

// itoa is a tiny dependency-free int formatter (avoids importing strconv just
// for the detail string).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
