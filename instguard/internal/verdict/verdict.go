// Package verdict collapses the per-finding output of every check into the
// per-package decision the design requires: SAFE / REVIEW / BLOCK with the
// reasons. The mapping is a pure function over findings so it is exhaustively
// table tested and the policy is one place to read:
//
//   - any Critical or High finding for a package  -> BLOCK  (known-mal, obfuscated
//     install hook, declared-but-unlocked drift)
//   - any Medium finding                          -> REVIEW (a fresh release, a
//     non-MAL OSV advisory, a benign-but-present install hook)
//   - nothing at Medium-or-above                  -> SAFE
//
// Findings that name no package (project-level lockfile/AUR notes) are rolled up
// under a synthetic "<project>" entry so the CI gate still sees them.
package verdict

import (
	"sort"
	"strings"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

// Decisions.
const (
	Safe   = "SAFE"
	Review = "REVIEW"
	Block  = "BLOCK"
)

// ProjectScope is the synthetic package name for findings with no package set.
const ProjectScope = "<project>"

// Build groups findings by package and assigns each a verdict. pinned lists the
// (name->versions) of resolved packages so every pinned package gets a verdict
// even when it produced no findings (it is then SAFE). When a name resolved to
// more than one distinct version (the same package installed at two paths), all
// of them are recorded on the verdict so the roll-up stays honest. The result is
// sorted by package name for deterministic output.
func Build(findings []report.Finding, pinned map[string][]string) []report.Verdict {
	type acc struct {
		worst   report.Severity
		reasons []string
		version string
	}
	byPkg := map[string]*acc{}

	ensure := func(name string) *acc {
		if a, ok := byPkg[name]; ok {
			return a
		}
		a := &acc{worst: report.SeverityInfo, version: joinVersions(pinned[name])}
		byPkg[name] = a
		return a
	}

	// Seed every pinned package so clean ones are reported SAFE.
	for name := range pinned {
		ensure(name)
	}

	for _, f := range findings {
		name := f.Package
		if name == "" {
			name = ProjectScope
		}
		a := ensure(name)
		if f.Severity > a.worst {
			a.worst = f.Severity
		}
		if f.Severity >= report.SeverityMedium {
			a.reasons = append(a.reasons, f.Title)
		}
	}

	names := make([]string, 0, len(byPkg))
	for n := range byPkg {
		names = append(names, n)
	}
	sort.Strings(names)

	verdicts := make([]report.Verdict, 0, len(names))
	for _, n := range names {
		a := byPkg[n]
		verdicts = append(verdicts, report.Verdict{
			Package:  n,
			Version:  a.version,
			Decision: decide(a.worst),
			Reasons:  dedup(a.reasons),
		})
	}
	return verdicts
}

// decide maps a worst-severity to a decision.
func decide(worst report.Severity) string {
	switch {
	case worst >= report.SeverityHigh:
		return Block
	case worst >= report.SeverityMedium:
		return Review
	default:
		return Safe
	}
}

// AnyBlocked reports whether any verdict is BLOCK — the signal the `check`
// command turns into a CI-failing exit code.
func AnyBlocked(verdicts []report.Verdict) bool {
	for _, v := range verdicts {
		if v.Decision == Block {
			return true
		}
	}
	return false
}

// joinVersions renders the distinct resolved versions of a package for the
// verdict's Version field. A single version is shown bare; multiple (the same
// name installed at two paths) are comma-joined so the verdict names every
// version that was actually checked.
func joinVersions(versions []string) string {
	return strings.Join(versions, ", ")
}

func dedup(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
