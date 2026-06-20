package preflight

import (
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// Tool is the report tool name preflight emits under, distinct from the "agent"
// run/scan reports so the collector/dashboard can tell readiness checks apart.
const Tool = "agent-preflight"

// ToReport turns the checks into a report.Report. Every NOT-OK check becomes a
// Finding with check="preflight.<name>"; OK checks are omitted (a clean report
// has no findings). The preflight Severity is mapped onto report.Severity:
//
//	info   → report.SeverityLow      (advisory; never makes a run "not clean")
//	medium → report.SeverityMedium   (soft blocker)
//	high   → report.SeverityHigh     (hard blocker)
//
// host labels the report; t is the report timestamp (injected for tests).
func ToReport(host string, t time.Time, checks []Check) report.Report {
	findings := make([]report.Finding, 0, len(checks))
	for _, c := range checks {
		if c.OK {
			continue
		}
		findings = append(findings, report.Finding{
			Check:    "preflight." + c.Name,
			Severity: mapSeverity(c.Severity),
			Title:    c.Detail,
			Detail:   c.Remedy,
		})
	}
	return report.New(Tool, host, "", t, findings)
}

// mapSeverity maps a preflight Severity onto the shared report.Severity scale.
func mapSeverity(s Severity) report.Severity {
	switch s {
	case SeverityHigh:
		return report.SeverityHigh
	case SeverityMedium:
		return report.SeverityMedium
	default:
		// info → Low: advisory findings stay below the Medium "clean" threshold,
		// so a host with only info-level gaps still reports clean / exit-ready.
		return report.SeverityLow
	}
}

// Ready reports whether every HARD/SOFT blocker passed. A check that is not OK
// at Medium or High severity makes the host NOT ready; info-level not-OK checks
// (advisory) do not. This is the decision the exit code is built on.
func Ready(checks []Check) bool {
	for _, c := range checks {
		if !c.OK && c.Severity >= SeverityMedium {
			return false
		}
	}
	return true
}

// Exit-code semantics, matching the milestone spec:
//
//	0 → host is ready to arm enforcement (no medium/high blockers)
//	2 → host is NOT ready (at least one medium/high blocker)
//	1 → the verifier itself errored (reserved for the caller; ExitCode never
//	    returns it — a probe failing to read host state is modelled as a
//	    not-OK Check, not a verifier error)
const (
	ExitReady    = 0
	ExitNotReady = 2
	ExitError    = 1
)

// ExitCode returns ExitReady when the host is ready and ExitNotReady otherwise.
// The verifier-error code (ExitError) is the caller's to return when Run could
// not be invoked at all; ExitCode itself only distinguishes ready/not-ready.
func ExitCode(checks []Check) int {
	if Ready(checks) {
		return ExitReady
	}
	return ExitNotReady
}
