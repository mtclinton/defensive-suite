// Package gitleaks orchestrates the gitleaks secret scanner over a directory and
// parses its JSON report into credsentinel findings. gitleaks is fast regex
// matching (the pre-commit class of detector): it tells you a secret *shape* is
// present, not whether it is live — so its findings cap at High. A missing
// gitleaks binary degrades to an informational finding; the built-in fallback
// scanner then carries the load.
package gitleaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/runner"
)

// finding mirrors the fields credsentinel uses from a gitleaks JSON report entry.
// gitleaks emits a JSON array of these on stdout with --report-format json
// --report-path - (or to a file). Extra fields are ignored.
type finding struct {
	Description string `json:"Description"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	StartLine   int    `json:"StartLine"`
	Secret      string `json:"Secret"`
	Match       string `json:"Match"`
}

// Args builds the gitleaks invocation for scanning a directory tree. It uses
// `detect --no-git` so it scans files on disk (not git history), reports JSON to
// stdout, and stays quiet otherwise.
func Args(dir string) []string {
	return []string{
		"detect",
		"--source", dir,
		"--no-git",
		"--report-format", "json",
		"--report-path", "-",
		"--no-banner",
		"--exit-code", "0", // we read the JSON; don't rely on exit code for control flow
	}
}

// ParseReport parses a gitleaks JSON report (an array) into findings. gitleaks
// writes an empty array (or nothing) when clean. Malformed JSON yields an error.
func ParseReport(out string) ([]finding, error) {
	s := strings.TrimSpace(out)
	if s == "" || s == "null" {
		return nil, nil
	}
	var fs []finding
	if err := json.Unmarshal([]byte(s), &fs); err != nil {
		return nil, err
	}
	return fs, nil
}

// redact masks the secret so the finding never re-leaks it.
func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6)
}

// toFindings converts gitleaks findings to report findings (High; shape, not
// liveness).
func toFindings(fs []finding) []report.Finding {
	var out []report.Finding
	for _, f := range fs {
		out = append(out, report.Finding{
			Check: "gitleaks", Severity: report.SeverityHigh, Path: f.File,
			Title:     "gitleaks matched a secret pattern (shape, not verified live)",
			Detail:    fmt.Sprintf("rule=%s line=%d secret=%s", f.RuleID, f.StartLine, redact(f.Secret)),
			Technique: "T1552.001",
		})
	}
	return out
}

// Scan runs gitleaks against dir and maps the result to findings. A missing
// binary is reported as Info (the built-in fallback covers it); a parse failure
// is Low (operational, not a compromise signal).
func Scan(ctx context.Context, r runner.Runner, dir string) []report.Finding {
	res, err := r.Run(ctx, "gitleaks", Args(dir)...)
	if errors.Is(err, runner.ErrNotFound) {
		return []report.Finding{{
			Check: "gitleaks", Severity: report.SeverityInfo, Path: dir,
			Title: "gitleaks not installed; using built-in fallback scanner for this path",
		}}
	}
	if err != nil {
		return []report.Finding{{
			Check: "gitleaks", Severity: report.SeverityLow, Path: dir,
			Title: "gitleaks run error", Detail: err.Error(),
		}}
	}
	fs, perr := ParseReport(res.Stdout)
	if perr != nil {
		return []report.Finding{{
			Check: "gitleaks", Severity: report.SeverityLow, Path: dir,
			Title: "could not parse gitleaks report", Detail: perr.Error(),
		}}
	}
	if len(fs) == 0 {
		return []report.Finding{{
			Check: "gitleaks", Severity: report.SeverityInfo, Path: dir,
			Title: "gitleaks found no secret patterns",
		}}
	}
	return toFindings(fs)
}
