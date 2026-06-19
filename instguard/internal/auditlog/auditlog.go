// Package auditlog implements the post-install pass the design mandates: scan
// ~/.npm/_logs for evidence that a lifecycle script (preinstall/install/
// postinstall/prepare) actually ran. npm records each lifecycle invocation in
// its debug logs; a postinstall that executed after the fact is the thing you
// most want to know about if you ran a bare `npm install`. Parsing is a pure
// function over log text so it is table tested; Scan only adds the filesystem
// read of the log directory.
package auditlog

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

// maxLogBytes bounds each npm log read. Install scripts can write into
// ~/.npm/_logs, so an unbounded os.ReadFile is a DoS vector; 8 MiB is far above
// any real debug log. Truncation is fine — ParseLog scans line by line, so a
// capped read still surfaces the lifecycle events in the leading content.
const maxLogBytes = 8 << 20

// lifecycleLine matches an npm debug-log line announcing a lifecycle script run,
// across the formats npm has used, e.g.:
//
//	1234 verbose lifecycle some-pkg@1.2.3~postinstall: PATH: ...
//	42 info run some-pkg@1.2.3 postinstall node_modules/some-pkg node build.js
//	silly reify ... postinstall
//
// Group 1 captures the package spec up to the '~' or ' ' that precedes the
// script; the captured spec still carries its @version, which stripVersion
// trims off so the package name keys the event.
var lifecycleLine = regexp.MustCompile(
	`(?i)(?:lifecycle|run)\s+(\S+?)[~ ](preinstall|install|postinstall|prepare)\b`)

// stripVersion turns "left-pad@1.2.3" into "left-pad", preserving a scoped
// package's leading '@' (e.g. "@scope/pkg@1.0.0" -> "@scope/pkg").
func stripVersion(spec string) string {
	at := strings.LastIndex(spec, "@")
	if at <= 0 { // no '@', or it is the scope sigil at index 0
		return spec
	}
	return spec[:at]
}

// fallbackLifecycle catches the keyword alone (for log formats that don't carry
// a package spec on the same line), so a postinstall is never missed entirely.
var fallbackLifecycle = regexp.MustCompile(`(?i)\b(preinstall|postinstall|prepare)\b`)

// Event is one detected lifecycle-script run.
type Event struct {
	Package string // best-effort package spec, may be ""
	Script  string // preinstall | install | postinstall | prepare
}

// ParseLog extracts lifecycle events from one log file's text. Results are
// de-duplicated by (package, script) and sorted for deterministic output.
func ParseLog(content string) []Event {
	seen := map[Event]bool{}
	for _, line := range strings.Split(content, "\n") {
		if m := lifecycleLine.FindStringSubmatch(line); m != nil {
			ev := Event{Package: stripVersion(m[1]), Script: strings.ToLower(m[2])}
			seen[ev] = true
			continue
		}
		// Only fall back when the line clearly refers to running a lifecycle
		// script, to avoid matching prose mentions of the words.
		if strings.Contains(strings.ToLower(line), "lifecycle") {
			if m := fallbackLifecycle.FindStringSubmatch(line); m != nil {
				seen[Event{Script: strings.ToLower(m[1])}] = true
			}
		}
	}
	events := make([]Event, 0, len(seen))
	for e := range seen {
		events = append(events, e)
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Package != events[j].Package {
			return events[i].Package < events[j].Package
		}
		return events[i].Script < events[j].Script
	})
	return events
}

// Findings turns events into report findings. postinstall/preinstall/install are
// the ones that execute attacker-controlled code automatically; a prepare hook
// runs on local installs too. Each ran-script is Medium ("a hook executed; if you
// did not use --ignore-scripts, audit it"), so the post-install pass surfaces in
// the report's worst-severity roll-up.
func Findings(logPath string, events []Event) []report.Finding {
	var findings []report.Finding
	for _, e := range events {
		pkg := e.Package
		detail := "lifecycle script ran during a previous install"
		if pkg != "" {
			detail = pkg + " " + e.Script + " ran during a previous install"
		}
		findings = append(findings, report.Finding{
			Check: "audit", Severity: report.SeverityMedium, Path: logPath, Package: pkg,
			Title:     "npm " + e.Script + " hook executed (post-install evidence)",
			Detail:    detail + "; if this was a bare `npm install`, treat the package as having run code",
			Technique: "T1059",
		})
	}
	return findings
}

// Scan reads every *.log under dir and reports the lifecycle scripts that ran.
// A missing or empty directory yields a single Info finding (nothing to audit),
// never an error — degrade gracefully.
func Scan(dir string) ([]report.Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []report.Finding{{
				Check: "audit", Severity: report.SeverityInfo, Path: dir,
				Title: "no npm log directory found; nothing to audit",
			}}, nil
		}
		return nil, err
	}
	var logs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".log") {
			logs = append(logs, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(logs)

	var findings []report.Finding
	for _, p := range logs {
		b, err := readLogBounded(p, maxLogBytes)
		if err != nil {
			continue
		}
		findings = append(findings, Findings(p, ParseLog(string(b)))...)
	}
	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			Check: "audit", Severity: report.SeverityInfo, Path: dir,
			Title: "no lifecycle scripts found in npm logs",
		})
	}
	return findings, nil
}

// readLogBounded reads at most maxBytes from path. Truncation is acceptable for
// line scanning, so it simply caps the read with an io.LimitReader rather than
// flagging an overflow.
func readLogBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

// DefaultLogsDir returns the npm logs directory for the current user, honoring an
// explicit override. Blank override falls back to $HOME/.npm/_logs.
func DefaultLogsDir(override string) string {
	if override != "" {
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".npm/_logs"
	}
	return filepath.Join(home, ".npm", "_logs")
}
