package sysctl

import (
	"os"
	"strings"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
)

// ParseProfile parses a target profile file (sysctl.conf-style "key = value"
// lines, '#'/';' comments) into a Want override map. A profile only overrides
// the Want of the built-in goal targets; it does not introduce new keys, so the
// severities and allowed-value semantics stay with the built-in GoalProfile.
func ParseProfile(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if key != "" && val != "" {
			out[key] = val
		}
	}
	return out
}

// ApplyProfile overlays Want overrides from a parsed profile onto a copy of the
// goal targets. It changes ONLY the recommended Want value; it KEEPS the
// built-in AllowedValues so an already-stricter-than-target host still passes.
//
// Narrowing AllowedValues to exactly the profile value (the previous behavior)
// flagged hosts that are STRICTER than the target — e.g. yama.ptrace_scope=3
// when the profile pins 2, or unprivileged_bpf_disabled=1 / kptr_restrict=1
// when the profile pins 2 — as High DIFFERENT. That made the daily oneshot unit
// enter 'failed' on legitimately-hardened hosts, contradicting the goal of
// "want 1 or 2" and the profile's own comments. A profile sets the recommended
// value; it does not reject the also-accepted (or stricter) ones.
func ApplyProfile(base []Target, overrides map[string]string) []Target {
	out := make([]Target, len(base))
	copy(out, base)
	for i := range out {
		if w, ok := overrides[out[i].Key]; ok {
			out[i].Want = w
		}
	}
	return out
}

// LoadProfile reads and applies a profile file to the goal targets. A blank path
// returns the built-in GoalProfile unchanged.
func LoadProfile(path string) ([]Target, error) {
	base := GoalProfile()
	if path == "" {
		return base, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return base, err
	}
	return ApplyProfile(base, ParseProfile(string(b))), nil
}

// EvaluateLockdown turns the parsed lockdown mode into an OK/DIFFERENT row and a
// finding. The goal is "confidentiality" (the strongest mode); "integrity" is a
// partial credit at Low; "none"/unsupported is a Medium drift. Per DESIGN.md,
// lockdown is what makes IronWorm's best hiding tricks fail.
func EvaluateLockdown(mode string, supported bool) (report.SysctlRow, report.Finding, bool) {
	const key = "kernel.lockdown"
	row := report.SysctlRow{
		Key: key, Want: "confidentiality",
		Comment: "kernel lockdown — hidden processes/modules reappear under confidentiality",
	}
	if !supported {
		row.Got = "(unsupported)"
		row.Status = StatusUnknown
		return row, report.Finding{
			Check: "lockdown", Severity: report.SeverityLow, Path: key,
			Title:  "kernel lockdown not available (CONFIG_SECURITY_LOCKDOWN_LSM off or LSM not active)",
			Detail: "want=confidentiality",
		}, true
	}
	row.Got = mode
	switch mode {
	case "confidentiality":
		row.Status = StatusOK
		return row, report.Finding{}, false
	case "integrity":
		row.Status = StatusDifferent
		return row, report.Finding{
			Check: "lockdown", Severity: report.SeverityLow, Path: key,
			Title:  "kernel lockdown is integrity, not confidentiality",
			Detail: "want=confidentiality got=integrity",
		}, true
	default:
		row.Status = StatusDifferent
		return row, report.Finding{
			Check: "lockdown", Severity: report.SeverityMedium, Path: key,
			Title:     "kernel lockdown is off",
			Detail:    "want=confidentiality got=" + mode,
			Technique: "T1014",
		}, true
	}
}
