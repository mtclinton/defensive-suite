// Package aide runs `aide --check` against the off-host AIDE database (the trust
// anchor) and summarizes added/removed/changed entries. authwatch never writes
// the database from a check run; initialization is a separate, explicit step the
// operator runs against off-host media.
package aide

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

// Summary is the parsed result of an AIDE check.
type Summary struct {
	Added       int
	Removed     int
	Changed     int
	Differences bool
}

// aideCount matches both modern ("Added entries:") and older ("Added files:")
// AIDE summary lines.
var aideCount = regexp.MustCompile(`(?i)\b(Added|Removed|Changed)\s+(?:entries|files)\s*:\s*(\d+)`)

// ParseCheck extracts the change summary from AIDE's report.
func ParseCheck(output string) Summary {
	var s Summary
	for _, m := range aideCount.FindAllStringSubmatch(output, -1) {
		n, _ := strconv.Atoi(m[2])
		switch strings.ToLower(m[1]) {
		case "added":
			s.Added = n
		case "removed":
			s.Removed = n
		case "changed":
			s.Changed = n
		}
	}
	s.Differences = strings.Contains(output, "found differences") || s.Added+s.Removed+s.Changed > 0
	return s
}

// Run invokes `aide --check` and maps the result to findings. A missing aide
// binary degrades to an informational finding rather than an error.
func Run(ctx context.Context, r runner.Runner, configPath string) []report.Finding {
	args := []string{"--check"}
	if configPath != "" {
		args = []string{"--config=" + configPath, "--check"}
	}
	res, err := r.Run(ctx, "aide", args...)
	if errors.Is(err, runner.ErrNotFound) {
		return []report.Finding{{
			Check: "aide", Severity: report.SeverityInfo,
			Title: "aide not installed; integrity database check skipped",
		}}
	}
	if err != nil {
		return []report.Finding{{
			Check: "aide", Severity: report.SeverityLow,
			Title: "aide check error", Detail: err.Error(),
		}}
	}
	sum := ParseCheck(res.Stdout + "\n" + res.Stderr)
	if !sum.Differences && res.ExitCode == 0 {
		return []report.Finding{{
			Check: "aide", Severity: report.SeverityInfo,
			Title: "AIDE database matches the filesystem",
		}}
	}
	return []report.Finding{{
		Check: "aide", Severity: report.SeverityHigh,
		Title:     "AIDE reports filesystem differences from baseline database",
		Detail:    fmt.Sprintf("added=%d removed=%d changed=%d", sum.Added, sum.Removed, sum.Changed),
		Technique: "T1565.001",
	}}
}
