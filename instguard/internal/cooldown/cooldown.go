// Package cooldown enforces a release-age quarantine: a version published within
// the last N days is too fresh to trust, because most malicious uploads earn a
// MAL- classification within ~3 days of publication (per DESIGN.md). The core is
// a pure comparison with an injected "now", so the policy is fully tested without
// a clock or the network; publish dates come from package metadata supplied by
// the caller.
package cooldown

import (
	"fmt"
	"time"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

// Release is a (package, version, published-at) tuple. PublishedAt is the
// registry's publication timestamp for the resolved version.
type Release struct {
	Package     string
	Version     string
	PublishedAt time.Time
}

// TooFresh reports whether published is within the cooldown window ending at
// now. A zero-day or negative window disables the cooldown (always false). A
// future publish date (clock skew or a spoofed timestamp) is treated as fresh.
func TooFresh(published, now time.Time, days int) bool {
	if days <= 0 {
		return false
	}
	if published.IsZero() {
		return false // unknown publish date — not this check's job to flag
	}
	age := now.Sub(published)
	if age < 0 {
		return true // published "in the future": suspicious, quarantine it
	}
	window := time.Duration(days) * 24 * time.Hour
	return age < window
}

// AgeDays returns the whole-day age of a release relative to now (negative if the
// timestamp is in the future). Used only for the finding detail string.
func AgeDays(published, now time.Time) int {
	return int(now.Sub(published).Hours() / 24)
}

// Check evaluates one release against the cooldown policy and returns a finding
// when it is too fresh. A version inside the window is Medium: review it, do not
// hard-block — a legitimate fresh release is common, the malicious-vs-benign call
// is what the OSV and hook checks make.
func Check(r Release, now time.Time, days int) []report.Finding {
	if !TooFresh(r.PublishedAt, now, days) {
		return nil
	}
	var detail string
	if r.PublishedAt.After(now) {
		detail = fmt.Sprintf("%s@%s publish date %s is in the future relative to %s",
			r.Package, r.Version, r.PublishedAt.Format(time.RFC3339), now.Format(time.RFC3339))
	} else {
		detail = fmt.Sprintf("%s@%s published %s (%d day(s) ago); cooldown is %d day(s)",
			r.Package, r.Version, r.PublishedAt.Format(time.RFC3339), AgeDays(r.PublishedAt, now), days)
	}
	return []report.Finding{{
		Check: "cooldown", Severity: report.SeverityMedium, Package: r.Package,
		Title:     "version published inside the release-age cooldown window",
		Detail:    detail,
		Technique: "T1195.002",
	}}
}

// CheckAll evaluates a batch of releases.
func CheckAll(releases []Release, now time.Time, days int) []report.Finding {
	var findings []report.Finding
	for _, r := range releases {
		findings = append(findings, Check(r, now, days)...)
	}
	return findings
}
