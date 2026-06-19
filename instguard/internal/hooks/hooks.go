// Package hooks scans the npm lifecycle scripts that run at install time
// (preinstall / install / postinstall / prepare) for the patterns malicious
// packages use to execute before any `import`: piping a remote download into a
// shell, inline `node -e` / `eval`, base64/atob-decoded blobs, and disabling TLS
// verification. ScanScripts is a pure function over the parsed scripts map so the
// whole detector is table tested; nothing here ever executes a script.
package hooks

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

// installLifecycle is the set of script names npm runs automatically during an
// install. These are the ones that execute without the user invoking them.
var installLifecycle = []string{"preinstall", "install", "postinstall", "prepare"}

// pattern pairs a detector with the finding it raises.
type pattern struct {
	name     string
	re       *regexp.Regexp
	severity report.Severity
	title    string
}

// patterns are ordered most-to-least specific; all matches on a script are
// reported. Each regex is deliberately broad — an install hook has no legitimate
// reason to fetch-and-execute or disable TLS, so false positives are acceptable.
var patterns = []pattern{
	{
		name:     "curl-pipe-sh",
		re:       regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^|;&\n]*\|[^|\n]*\b(sh|bash|zsh|node|python[0-9.]*|perl|ruby)\b`),
		severity: report.SeverityCritical,
		title:    "remote download piped directly into a shell/interpreter",
	},
	{
		// A base64 decode whose output is piped into a shell is decode-then-RCE —
		// the most dangerous form of the base64/atob-blob pattern the design names.
		name:     "decode-pipe-sh",
		re:       regexp.MustCompile(`(?i)\bbase64\b[^|\n]*\s(-d|--decode)\b[^|\n]*\|[^|\n]*\b(sh|bash|zsh|node)\b`),
		severity: report.SeverityCritical,
		title:    "base64-decoded blob piped directly into a shell/interpreter",
	},
	{
		name:     "node-eval-flag",
		re:       regexp.MustCompile(`(?i)\bnode\b[^\n]*\s-e\b`),
		severity: report.SeverityHigh,
		title:    "inline `node -e` execution in an install hook",
	},
	{
		name:     "eval-call",
		re:       regexp.MustCompile(`(?i)\beval\s*\(`),
		severity: report.SeverityHigh,
		title:    "`eval(` in an install hook",
	},
	{
		name:     "atob-decode",
		re:       regexp.MustCompile(`(?i)\b(atob|Buffer\.from)\b[^\n]*\bbase64\b|(?i)\batob\s*\(`),
		severity: report.SeverityHigh,
		title:    "base64/atob-decoded blob executed in an install hook",
	},
	{
		name:     "base64-pipe-decode",
		re:       regexp.MustCompile(`(?i)\bbase64\b[^\n]*\s(-d|--decode)\b`),
		severity: report.SeverityHigh,
		title:    "shell base64 decode in an install hook",
	},
	{
		name:     "tls-disabled",
		re:       regexp.MustCompile(`(?i)NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0`),
		severity: report.SeverityHigh,
		title:    "install hook disables TLS certificate verification (NODE_TLS_REJECT_UNAUTHORIZED=0)",
	},
}

// ScanScript runs every pattern against one script body and returns the findings
// for it. scriptName is the lifecycle key (e.g. "postinstall"); it is recorded
// in the finding so an operator knows which hook fires.
func ScanScript(scriptName, body string) []report.Finding {
	var findings []report.Finding
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return findings
	}
	for _, p := range patterns {
		if p.re.MatchString(body) {
			findings = append(findings, report.Finding{
				Check: "hooks", Severity: p.severity,
				Title:     p.title,
				Detail:    fmt.Sprintf("%s: %s", scriptName, oneLine(trimmed)),
				Technique: "T1059",
			})
		}
	}
	return findings
}

// ScanScripts scans only the install-lifecycle scripts in a package.json scripts
// map. pkgName, when set, tags the findings so a per-package verdict can be built.
// Scripts are iterated in a fixed order for deterministic output.
func ScanScripts(pkgName string, scripts map[string]string) []report.Finding {
	var findings []report.Finding
	for _, name := range installLifecycle {
		body, ok := scripts[name]
		if !ok {
			continue
		}
		for _, f := range ScanScript(name, body) {
			f.Package = pkgName
			findings = append(findings, f)
		}
	}
	return findings
}

// InstallScriptNames returns the install-lifecycle script names actually present
// in the map, sorted. An install hook that is present but matches no malicious
// pattern still merits an Info note — it runs arbitrary code at install time.
func InstallScriptNames(scripts map[string]string) []string {
	var present []string
	for _, name := range installLifecycle {
		if _, ok := scripts[name]; ok {
			present = append(present, name)
		}
	}
	sort.Strings(present)
	return present
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
