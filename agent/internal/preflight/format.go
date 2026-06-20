package preflight

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// WriteTable renders the checks as a readable aligned table to w, followed by a
// one-line verdict. It is pure formatting — it reads nothing from the host — so
// it is unit-testable against a buffer.
//
// Each row: STATUS  SEVERITY  NAME  DETAIL. OK checks show "ok" with a blank
// severity; not-OK checks show "FAIL" and their severity. The verdict line says
// READY / NOT READY and, when not ready, lists the blocking checks so the
// operator sees exactly what to fix before consulting deploy/ENFORCE.md.
func WriteTable(w io.Writer, checks []Check) {
	fmt.Fprintln(w, "agentd preflight — host readiness for arming enforcement (READ-ONLY; nothing changed)")
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tSEVERITY\tCHECK\tDETAIL")
	for _, c := range checks {
		status := "ok"
		sev := ""
		if !c.OK {
			status = "FAIL"
			sev = c.Severity.String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", status, sev, c.Name, oneLine(c.Detail))
	}
	_ = tw.Flush()

	// Remedies for the not-OK checks, so the operator does not have to cross-
	// reference the table with ENFORCE.md to know the next action.
	var remedies []string
	for _, c := range checks {
		if !c.OK && c.Remedy != "" {
			remedies = append(remedies, fmt.Sprintf("  - %s: %s", c.Name, oneLine(c.Remedy)))
		}
	}
	if len(remedies) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "remedies:")
		for _, r := range remedies {
			fmt.Fprintln(w, r)
		}
	}

	fmt.Fprintln(w)
	if Ready(checks) {
		fmt.Fprintln(w, "verdict: READY — no medium/high blockers. Arm ONE policy at a time, VM-first (deploy/ENFORCE.md).")
		return
	}
	var blockers []string
	for _, c := range checks {
		if !c.OK && c.Severity >= SeverityMedium {
			blockers = append(blockers, c.Name)
		}
	}
	fmt.Fprintf(w, "verdict: NOT READY — blockers: %s. Resolve these before arming (deploy/ENFORCE.md).\n",
		strings.Join(blockers, ", "))
}

// oneLine collapses any embedded newlines so a Detail/Remedy can't break the
// table layout.
func oneLine(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
}
