// Package tools wraps the external compliance/hardening scanners the DESIGN doc
// names — Lynis (hardening index), OpenSCAP/oscap (XCCDF pass/fail), and
// `systemd-analyze security` (per-service exposure) — parsing their output into
// findings. Every wrapper degrades gracefully: an absent tool yields an Info
// "not installed" finding, never an error that blinds the whole run.
package tools

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
	"github.com/mtclinton/defensive-suite/posturescan/internal/runner"
)

// ---- Lynis ----

// ParseLynisIndex extracts the hardening index from `lynis audit system` stdout
// or a report.dat. It accepts both the human line "Hardening index : 67 [...]"
// and the report.dat line "hardening_index=67". Returns ok=false when absent.
func ParseLynisIndex(output string) (int, bool) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "hardening_index="):
			return atoiOK(strings.TrimPrefix(line, "hardening_index="))
		case strings.Contains(low, "hardening index"):
			// "Hardening index : 67 [############        ]"
			_, rest, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			rest = strings.TrimSpace(rest)
			f := strings.Fields(rest) // drop the bar graph
			if len(f) == 0 {
				// "hardening index :" with nothing after the colon — Fields("")[0]
				// would panic and crash the whole run; skip the empty line instead.
				continue
			}
			rest = f[0]
			if n, ok := atoiOK(rest); ok {
				return n, true
			}
		}
	}
	return 0, false
}

func atoiOK(s string) (int, bool) {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Lynis runs `lynis audit system` (quiet) and reports the hardening index. Per
// THREAT_MODEL.md a hardening index below ~70 means "remediate before further
// building", so below 70 is Medium and below 50 is High.
func Lynis(ctx context.Context, r runner.Runner) []report.Finding {
	res, err := r.Run(ctx, "lynis", "audit", "system", "--quiet", "--no-colors")
	if errors.Is(err, runner.ErrNotFound) {
		return []report.Finding{{
			Check: "lynis", Severity: report.SeverityInfo,
			Title: "lynis not installed; hardening index skipped",
		}}
	}
	if err != nil {
		return []report.Finding{{
			Check: "lynis", Severity: report.SeverityLow,
			Title: "lynis run error", Detail: err.Error(),
		}}
	}
	idx, ok := ParseLynisIndex(res.Stdout)
	if !ok {
		return []report.Finding{{
			Check: "lynis", Severity: report.SeverityLow,
			Title: "could not parse lynis hardening index from output",
		}}
	}
	sev := report.SeverityInfo
	switch {
	case idx < 50:
		sev = report.SeverityHigh
	case idx < 70:
		sev = report.SeverityMedium
	}
	return []report.Finding{{
		Check: "lynis", Severity: sev,
		Title:  "lynis hardening index " + strconv.Itoa(idx) + "/100",
		Detail: "threat-model threshold is ~70; below that, remediate before further building",
	}}
}

// ---- OpenSCAP / oscap ----

// OscapResult is the parsed pass/fail tally from an XCCDF evaluation.
type OscapResult struct {
	Pass  int
	Fail  int
	Error int
	Total int
}

// ParseOscapResults tallies rule results from `oscap xccdf eval` stdout, where
// each evaluated rule prints "Result   pass" / "Result   fail" etc. Pure.
func ParseOscapResults(output string) OscapResult {
	var res OscapResult
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Result") {
			continue
		}
		_, val, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "pass", "fixed":
			res.Pass++
			res.Total++
		case "fail":
			res.Fail++
			res.Total++
		case "error":
			res.Error++
			res.Total++
		case "notapplicable", "notchecked", "notselected", "informational", "unknown":
			// not scored
		}
	}
	return res
}

// Oscap runs an XCCDF evaluation against the given datastream and profile and
// reports the pass/fail tally. Blank datastream/profile means the host did not
// configure OpenSCAP content, so the check is skipped at Info.
func Oscap(ctx context.Context, r runner.Runner, datastream, profile string) []report.Finding {
	if datastream == "" || profile == "" {
		return []report.Finding{{
			Check: "oscap", Severity: report.SeverityInfo,
			Title: "no OpenSCAP datastream/profile configured; XCCDF scoring skipped",
		}}
	}
	res, err := r.Run(ctx, "oscap", "xccdf", "eval", "--profile", profile, datastream)
	if errors.Is(err, runner.ErrNotFound) {
		return []report.Finding{{
			Check: "oscap", Severity: report.SeverityInfo,
			Title: "oscap not installed; XCCDF scoring skipped",
		}}
	}
	if err != nil {
		return []report.Finding{{
			Check: "oscap", Severity: report.SeverityLow,
			Title: "oscap run error", Detail: err.Error(),
		}}
	}
	// oscap exits 2 when rules fail — that is a finding, not an operational error.
	tally := ParseOscapResults(res.Stdout)
	if tally.Total == 0 {
		return []report.Finding{{
			Check: "oscap", Severity: report.SeverityLow,
			Title: "oscap produced no rule results (check datastream/profile)",
		}}
	}
	pct := tally.Pass * 100 / tally.Total
	sev := report.SeverityInfo
	switch {
	case pct < 60:
		sev = report.SeverityHigh
	case pct < 85:
		sev = report.SeverityMedium
	}
	return []report.Finding{{
		Check: "oscap", Severity: sev,
		Title: "OpenSCAP " + profile + ": " + strconv.Itoa(pct) + "% pass",
		Detail: "pass=" + strconv.Itoa(tally.Pass) + " fail=" + strconv.Itoa(tally.Fail) +
			" error=" + strconv.Itoa(tally.Error),
	}}
}
