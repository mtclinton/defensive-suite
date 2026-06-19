// Package check runs every egresswatch check in sequence and assembles the
// Report. A failure in one check never aborts the others — each degrades to a
// finding so a single missing tool can't blind the whole run.
package check

import (
	"context"
	"os"
	"time"

	"github.com/mtclinton/defensive-suite/egresswatch/internal/config"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/egress"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/report"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/runner"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/triage"
)

// Options tunes a run. Clock is injectable for deterministic tests.
type Options struct {
	Clock func() time.Time
	// SkipTriage / SkipEgress let the subcommands run just one half.
	SkipTriage bool
	SkipEgress bool
}

// Run executes the configured checks and returns the assembled report.
func Run(ctx context.Context, cfg config.Config, r runner.Runner, opts Options) report.Report {
	clock := time.Now
	if opts.Clock != nil {
		clock = opts.Clock
	}
	host, _ := os.Hostname()

	var findings []report.Finding
	if !opts.SkipTriage {
		findings = append(findings, triage.Scan(cfg.ProcDir, nil)...)
	}
	if !opts.SkipEgress {
		findings = append(findings, egress.Scan(ctx, r, cfg.AllowlistPath, cfg.ConnSource, cfg.ProcDir)...)
	}
	return report.New("egresswatch", host, clock(), findings)
}
