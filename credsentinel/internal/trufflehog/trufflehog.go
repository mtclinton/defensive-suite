// Package trufflehog orchestrates TruffleHog over a path and parses its NDJSON
// output. TruffleHog's value over a regex scanner is verification: it calls the
// provider API to decide whether a found credential is actually *live*. credsentinel
// runs it with --results=verified so only confirmed-live hits come back — and a
// verified-live credential is a Critical "rotate now", the worst thing the
// exposure scanner can find. A missing binary degrades to an informational
// finding.
package trufflehog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/runner"
)

// result mirrors the subset of TruffleHog's NDJSON result object credsentinel
// uses. TruffleHog emits one JSON object per line. Field names follow its v3
// schema (DetectorName, Verified, Raw, plus a nested SourceMetadata for the file
// path). Unused fields are ignored.
type result struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// Args builds the TruffleHog invocation for a filesystem path. --results=verified
// limits output to credentials confirmed live against the provider, which is what
// cuts triage to "rotate now"; --no-update keeps it offline/deterministic.
func Args(path string) []string {
	return []string{
		"filesystem", path,
		"--json",
		"--results=verified",
		"--no-update",
	}
}

// ParseNDJSON parses TruffleHog's line-delimited JSON. Blank lines and lines that
// are not result objects (e.g. log lines TruffleHog may interleave on stdout) are
// skipped rather than failing the whole parse, so one stray line never blinds a run.
func ParseNDJSON(out string) []result {
	var results []result
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var r result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		// A result object always carries a detector name; use that to reject
		// unrelated JSON log lines.
		if r.DetectorName == "" {
			continue
		}
		results = append(results, r)
	}
	return results
}

func (r result) file() string {
	if f := r.SourceMetadata.Data.Filesystem.File; f != "" {
		return f
	}
	return ""
}

func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6)
}

// toFindings maps TruffleHog results to report findings. A verified-live hit is
// Critical ("rotate now"); an unverified hit (only present if a future caller
// drops --results=verified) is High.
func toFindings(rs []result) []report.Finding {
	var out []report.Finding
	for _, r := range rs {
		sev := report.SeverityHigh
		title := "TruffleHog found a secret (unverified)"
		if r.Verified {
			sev = report.SeverityCritical
			title = "TruffleHog VERIFIED a LIVE credential — rotate now"
		}
		out = append(out, report.Finding{
			Check: "trufflehog", Severity: sev, Path: r.file(),
			Title:     title,
			Detail:    fmt.Sprintf("detector=%s verified=%t raw=%s", r.DetectorName, r.Verified, redact(r.Raw)),
			Technique: "T1552.001",
		})
	}
	return out
}

// Scan runs TruffleHog against path and maps the result to findings. A missing
// binary is Info (the built-in fallback covers the path); a run error is Low.
func Scan(ctx context.Context, r runner.Runner, path string) []report.Finding {
	res, err := r.Run(ctx, "trufflehog", Args(path)...)
	if errors.Is(err, runner.ErrNotFound) {
		return []report.Finding{{
			Check: "trufflehog", Severity: report.SeverityInfo, Path: path,
			Title: "trufflehog not installed; liveness verification unavailable for this path",
		}}
	}
	if err != nil {
		return []report.Finding{{
			Check: "trufflehog", Severity: report.SeverityLow, Path: path,
			Title: "trufflehog run error", Detail: err.Error(),
		}}
	}
	rs := ParseNDJSON(res.Stdout)
	if len(rs) == 0 {
		return []report.Finding{{
			Check: "trufflehog", Severity: report.SeverityInfo, Path: path,
			Title: "trufflehog found no verified-live credentials",
		}}
	}
	return toFindings(rs)
}
