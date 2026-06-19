// Package auditd reads the loaded audit ruleset (`auditctl -l`) and reports which
// of authwatch's expected watch rules are missing — a visibility gap, not a
// system change. authwatch never loads rules into the kernel; the ruleset ships
// under deploy/audit/ for the operator to install.
package auditd

import (
	"context"
	"fmt"
	"strings"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

// WatchRule is a single auditd path watch.
type WatchRule struct {
	Path  string
	Perms string
	Key   string
}

// ExpectedWatches mirrors deploy/audit/authwatch.rules — the trust-path watches
// named in the DESIGN.
var ExpectedWatches = []WatchRule{
	{Path: "/etc/ld.so.preload", Perms: "wa", Key: "authwatch_ldpreload"},
	{Path: "/etc/pam.d/", Perms: "wa", Key: "authwatch_pam"},
	{Path: "/etc/ssh/sshd_config", Perms: "wa", Key: "authwatch_sshd"},
	{Path: "/root/.ssh/", Perms: "wa", Key: "authwatch_rootssh"},
}

func normalize(path string) string {
	return strings.TrimRight(path, "/")
}

// ParseList parses `auditctl -l` output into the watch rules it contains.
func ParseList(output string) []WatchRule {
	var rules []WatchRule
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		var wr WatchRule
		isWatch := false
		for i := 0; i < len(fields); i++ {
			switch fields[i] {
			case "-w":
				if i+1 < len(fields) {
					wr.Path = fields[i+1]
					isWatch = true
					i++
				}
			case "-p":
				if i+1 < len(fields) {
					wr.Perms = fields[i+1]
					i++
				}
			case "-k", "-F":
				if i+1 < len(fields) {
					if fields[i] == "-k" {
						wr.Key = fields[i+1]
					}
					i++
				}
			}
		}
		if isWatch {
			rules = append(rules, wr)
		}
	}
	return rules
}

func permsCover(loaded, expected string) bool {
	for _, c := range expected {
		if !strings.ContainsRune(loaded, c) {
			return false
		}
	}
	return true
}

// MissingWatches returns the expected watches that are not loaded, or are loaded
// with permissions that do not cover the expected mask. An attacker can downgrade
// a watch (e.g. -p wa -> -p r) instead of deleting it to blind the write/attribute
// auditing while the path still appears present (T1562.001), so perms are compared
// too, not just paths.
func MissingWatches(loaded, expected []WatchRule) []WatchRule {
	loadedPerms := map[string]string{}
	for _, r := range loaded {
		np := normalize(r.Path)
		loadedPerms[np] += r.Perms
	}
	var missing []WatchRule
	for _, e := range expected {
		lp, present := loadedPerms[normalize(e.Path)]
		if !present || !permsCover(lp, e.Perms) {
			missing = append(missing, e)
		}
	}
	return missing
}

// Check reports any expected audit watch that is not currently loaded. Missing
// watches are Low severity (a config/visibility gap, possibly T1562.001 if an
// attacker cleared them) so they do not by themselves flip a run to non-clean.
func Check(ctx context.Context, r runner.Runner) []report.Finding {
	res, err := r.Run(ctx, "auditctl", "-l")
	if err != nil {
		return []report.Finding{{
			Check: "auditd", Severity: report.SeverityLow,
			Title: "auditctl unavailable; cannot confirm audit watches", Detail: errString(err),
		}}
	}
	// A non-zero exit (e.g. EPERM without CAP_AUDIT_READ) yields empty output that
	// would otherwise parse as "zero rules loaded" and emit a false "all watches
	// missing". Report it as unavailable instead.
	if res.ExitCode != 0 {
		return []report.Finding{{
			Check: "auditd", Severity: report.SeverityLow,
			Title:  "auditctl -l failed; cannot confirm audit watches",
			Detail: fmt.Sprintf("exit=%d %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}}
	}
	missing := MissingWatches(ParseList(res.Stdout), ExpectedWatches)
	if len(missing) == 0 {
		return []report.Finding{{
			Check: "auditd", Severity: report.SeverityInfo,
			Title: "all authwatch audit watches are loaded",
		}}
	}
	var findings []report.Finding
	for _, m := range missing {
		findings = append(findings, report.Finding{
			Check: "auditd", Severity: report.SeverityLow, Path: m.Path,
			Title:     "expected audit watch missing or weakened (reduced visibility)",
			Detail:    fmt.Sprintf("ensure deploy/audit/authwatch.rules is loaded: -w %s -p %s -k %s", m.Path, m.Perms, m.Key),
			Technique: "T1562.001",
		})
	}
	return findings
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
