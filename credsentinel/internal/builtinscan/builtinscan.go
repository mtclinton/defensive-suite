// Package builtinscan is the standard-library fallback secret scanner. When
// gitleaks and trufflehog are both absent, credsentinel still has to mean
// something — this finds the high-signal credential shapes the stealers harvest:
// AWS access keys, PEM private-key headers, and generic high-entropy / long
// opaque tokens. It is a regex + Shannon-entropy heuristic, deliberately tuned
// to favour the obvious cases (provider-prefixed keys, PEM headers) and to flag
// long random-looking tokens at lower confidence. It cannot verify liveness —
// that is trufflehog's job — so its worst severity is High, never the
// "verified-live" Critical.
package builtinscan

import (
	"math"
	"regexp"
	"strings"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
)

// Match is one secret-shaped hit in a file.
type Match struct {
	Rule     string
	Severity report.Severity
	Line     int
	// Redacted is a safe-to-log excerpt: the secret is masked so the finding
	// never re-leaks the credential into journald or the webhook.
	Redacted string
}

type rule struct {
	name     string
	severity report.Severity
	re       *regexp.Regexp
}

// Provider-prefixed key shapes are the highest-confidence hits — the prefix
// alone is near-unambiguous, so they are High regardless of entropy.
var rules = []rule{
	{"aws-access-key-id", report.SeverityHigh, regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b`)},
	{"aws-secret-access-key", report.SeverityHigh, regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})\b`)},
	{"github-token", report.SeverityHigh, regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b`)},
	{"gitlab-token", report.SeverityHigh, regexp.MustCompile(`\bglpat-[0-9A-Za-z\-_]{20,}\b`)},
	{"slack-token", report.SeverityHigh, regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{"google-api-key", report.SeverityHigh, regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"npm-token", report.SeverityHigh, regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`)},
	{"private-key-pem", report.SeverityHigh, regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`)},
}

// assignmentToken matches `key = "value"` / `key: value` style lines whose value
// is a long opaque token; these feed the entropy heuristic for generic secrets.
var assignmentToken = regexp.MustCompile(`(?i)(?:secret|token|passwd|password|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth)[A-Za-z0-9_]*\s*[=:]\s*["']?([A-Za-z0-9+/=_\-\.]{20,})`)

// ScanText runs every rule and the entropy heuristic over content and returns
// matches with the secret masked. It is a pure function: same input, same output.
func ScanText(content string) []Match {
	var matches []Match
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		ln := i + 1
		for _, r := range rules {
			if sm := r.re.FindStringSubmatch(line); sm != nil {
				// Prefer the captured secret value (group 1) over the whole match,
				// so the redaction — and thus the dedup key — is the secret itself,
				// not the surrounding `key=` assignment text.
				tok := sm[0]
				if len(sm) > 1 && sm[1] != "" {
					tok = sm[1]
				}
				matches = append(matches, Match{
					Rule: r.name, Severity: r.severity, Line: ln, Redacted: redact(tok),
				})
			}
		}
		// Generic high-entropy assignment: only flag when the value looks random.
		if m := assignmentToken.FindStringSubmatch(line); m != nil {
			tok := m[1]
			if !alreadyMatched(matches, ln, tok) && isHighEntropy(tok) {
				matches = append(matches, Match{
					Rule: "high-entropy-token", Severity: report.SeverityMedium, Line: ln, Redacted: redact(tok),
				})
			}
		}
	}
	return matches
}

// alreadyMatched avoids double-flagging a provider key that the generic
// heuristic would also catch on the same line.
func alreadyMatched(ms []Match, line int, tok string) bool {
	want := redact(tok)
	for _, m := range ms {
		if m.Line == line && m.Redacted == want {
			return true
		}
	}
	return false
}

// isHighEntropy returns true for tokens long and random-looking enough to be a
// secret rather than a path, URL, or English-ish identifier. The thresholds are
// deliberately conservative: a low-entropy long string (e.g. a file path) is not
// flagged, keeping the fallback scanner's false-positive rate down.
func isHighEntropy(s string) bool {
	if len(s) < 20 {
		return false
	}
	// Reject strings that are mostly a single character class with structure
	// (paths, dotted versions) — they read long but carry little entropy.
	e := shannonEntropy(s)
	// Base-64-ish secrets land around 4.5–6 bits/char; require a solid floor and
	// a mix of character classes so "aaaaaaaaaaaaaaaaaaaaaa" or "/usr/local/bin/x"
	// do not trip it.
	if e < 3.6 {
		return false
	}
	return classMix(s) >= 2
}

// shannonEntropy computes bits-per-character Shannon entropy.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// classMix counts how many of {lower, upper, digit, symbol} appear — a proxy for
// "looks like a generated token" vs. a single-class word or number.
func classMix(s string) int {
	var lower, upper, digit, sym bool
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		default:
			sym = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, sym} {
		if b {
			n++
		}
	}
	return n
}

// redact masks the middle of a secret, leaving a short prefix so triage can tell
// AKIA… from ghp… without the secret itself ever entering a log or report.
func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + "(len=" + itoa(len(s)) + ")"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// FindingsFor converts the matches in one file into report findings. kind is the
// credential class from the targets package (e.g. "AWS credentials"), or "" for
// a generic repo file.
func FindingsFor(path, kind string, ms []Match) []report.Finding {
	var findings []report.Finding
	for _, m := range ms {
		detail := "rule=" + m.Rule + " line=" + itoa(m.Line) + " match=" + m.Redacted
		if kind != "" {
			detail += " kind=" + kind
		}
		findings = append(findings, report.Finding{
			Check: "builtinscan", Severity: m.Severity, Path: path,
			Title:     "possible secret (built-in fallback scanner; liveness unverified)",
			Detail:    detail,
			Technique: "T1552.001",
		})
	}
	return findings
}
