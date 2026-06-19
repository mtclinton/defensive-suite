// Package preload detects LD_PRELOAD-based persistence (QLNX, T1574.006): a
// populated /etc/ld.so.preload, LD_PRELOAD assignments in shell init files, and
// LD_PRELOAD in systemd unit Environment= directives.
package preload

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
)

// ldPreloadAssign matches an LD_PRELOAD assignment (not a mere reference).
var ldPreloadAssign = regexp.MustCompile(`(?i)\bLD_PRELOAD\b\s*=`)

// ScanLdSoPreload flags any non-comment entry in /etc/ld.so.preload. An empty
// file is the clean state and produces nothing.
func ScanLdSoPreload(path, content string) []report.Finding {
	var findings []report.Finding
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		findings = append(findings, report.Finding{
			Check: "preload", Severity: report.SeverityCritical, Path: path,
			Title:     "ld.so.preload is populated",
			Detail:    t,
			Technique: "T1574.006", Sigma: "lnx_auditd_ld_so_preload_mod",
		})
	}
	return findings
}

// ScanShellInit flags LD_PRELOAD assignments in a shell init file.
func ScanShellInit(path, content string) []report.Finding {
	var findings []report.Finding
	for i, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if ldPreloadAssign.MatchString(t) {
			findings = append(findings, report.Finding{
				Check: "preload", Severity: report.SeverityHigh, Path: path,
				Title:     "LD_PRELOAD assignment in shell init file",
				Detail:    fmt.Sprintf("line %d: %s", i+1, t),
				Technique: "T1574.006",
			})
		}
	}
	return findings
}

// ScanSystemdUnit flags LD_PRELOAD inside a unit's Environment=/EnvironmentFile=
// directive.
func ScanSystemdUnit(path, content string) []report.Finding {
	var findings []report.Finding
	for i, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if (strings.HasPrefix(t, "Environment=") || strings.HasPrefix(t, "EnvironmentFile=")) &&
			strings.Contains(strings.ToUpper(t), "LD_PRELOAD") {
			findings = append(findings, report.Finding{
				Check: "preload", Severity: report.SeverityHigh, Path: path,
				Title:     "LD_PRELOAD in systemd unit Environment directive",
				Detail:    fmt.Sprintf("line %d: %s", i+1, t),
				Technique: "T1574.006",
			})
		}
	}
	return findings
}

func readFile(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// Scan runs all three preload checks: ld.so.preload, shell init globs, and
// systemd unit files under the given directories.
func Scan(ldPreloadPath string, shellGlobs, systemdDirs []string) []report.Finding {
	var findings []report.Finding

	if c, ok := readFile(ldPreloadPath); ok {
		findings = append(findings, ScanLdSoPreload(ldPreloadPath, c)...)
	}

	for _, glob := range shellGlobs {
		matches, err := filepath.Glob(glob)
		if err != nil {
			continue
		}
		for _, p := range matches {
			if c, ok := readFile(p); ok {
				findings = append(findings, ScanShellInit(p, c)...)
			}
		}
	}

	unitPatterns := []string{"*.service", "*.socket", "*.d/*.conf"}
	for _, dir := range systemdDirs {
		for _, pat := range unitPatterns {
			matches, err := filepath.Glob(filepath.Join(dir, pat))
			if err != nil {
				continue
			}
			for _, p := range matches {
				if c, ok := readFile(p); ok {
					findings = append(findings, ScanSystemdUnit(p, c)...)
				}
			}
		}
	}
	return findings
}
