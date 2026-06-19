// Package remediate generates — but never applies — the sysctl drop-in needed to
// move a host to the hardening target. Per the DESIGN doc and the build
// constraint, `posturescan remediate` is strictly DRY-RUN: it returns the
// /etc/sysctl.d/99-posturescan.conf content and the `sysctl --system` command as
// text for a human to review and run. Nothing here touches /etc, sysctl, or the
// kernel.
package remediate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
	"github.com/mtclinton/defensive-suite/posturescan/internal/sysctl"
)

// Plan is the dry-run remediation output: the drop-in file content and the
// privileged commands a human would run. It is data only — emitting it applies
// nothing.
type Plan struct {
	// DropInPath is where the file *would* go (e.g. /etc/sysctl.d/99-posturescan.conf).
	DropInPath string
	// DropInContent is the full file body to write there.
	DropInContent string
	// Commands are the privileged commands to run, in order, after review.
	Commands []string
	// Keys are the sysctl keys the plan sets (the drifted/unknown ones).
	Keys []string
	// Notes carry guidance for settings that a sysctl drop-in cannot apply
	// (kernel lockdown, module.sig_enforce — boot-time, not runtime-writable).
	Notes []string
}

// settableViaSysctl reports whether a key can be set by a sysctl.d drop-in.
// Kernel lockdown and module signature enforcement are boot-time settings, not
// runtime sysctls, so they get a Note instead of a drop-in line.
func settableViaSysctl(key string) bool {
	switch key {
	case "kernel.lockdown", "module.sig_enforce":
		return false
	default:
		return true
	}
}

// bootNote returns the human guidance for a boot-time-only setting.
func bootNote(key string) string {
	switch key {
	case "kernel.lockdown":
		return "kernel.lockdown is not a sysctl: set it at boot via the kernel cmdline " +
			"`lockdown=confidentiality` (or build with CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y). " +
			"It cannot be raised at runtime."
	case "module.sig_enforce":
		return "module.sig_enforce is a boot parameter, not a runtime sysctl: add " +
			"`module.sig_enforce=1` to the kernel cmdline (and ensure modules are signed) — " +
			"setting it via sysctl.d has no effect."
	default:
		return ""
	}
}

// BuildPlan generates the dry-run remediation for the drifted/unknown sysctl
// rows against the given targets. dropInPath is where the file would be written.
// now stamps the generated-at header (injected for deterministic tests). The
// returned Plan is pure data; the caller prints it.
func BuildPlan(targets []sysctl.Target, rows []report.SysctlRow, dropInPath string, now time.Time) Plan {
	wantByKey := map[string]string{}
	commentByKey := map[string]string{}
	for _, t := range targets {
		wantByKey[t.Key] = t.Want
		commentByKey[t.Key] = t.Comment
	}

	keys := sysctl.DiffKeys(rows) // sorted DIFFERENT/UNKNOWN keys
	plan := Plan{DropInPath: dropInPath, Keys: keys}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s — posturescan hardening drop-in (GENERATED, review before applying)\n", dropInPath)
	fmt.Fprintf(&b, "# generated %s by posturescan remediate (dry-run)\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# posturescan never writes this file or runs sysctl; apply it yourself after review.\n#\n")

	var sysctlKeys []string
	for _, k := range keys {
		if settableViaSysctl(k) {
			sysctlKeys = append(sysctlKeys, k)
			continue
		}
		if n := bootNote(k); n != "" {
			plan.Notes = append(plan.Notes, n)
		}
	}
	sort.Strings(sysctlKeys)

	if len(sysctlKeys) == 0 {
		b.WriteString("# (no runtime sysctls to change — host already matches the target profile)\n")
	}
	for _, k := range sysctlKeys {
		if c := commentByKey[k]; c != "" {
			fmt.Fprintf(&b, "# %s\n", c)
		}
		fmt.Fprintf(&b, "%s = %s\n", k, wantByKey[k])
	}
	plan.DropInContent = b.String()

	// Commands are shown, never executed. Quoting the heredoc body would be
	// fragile; the README/printed plan instructs the operator to paste the file.
	if len(sysctlKeys) > 0 {
		plan.Commands = []string{
			"# 1) write the reviewed drop-in (content above) to:",
			"sudo install -m 0644 /dev/stdin " + dropInPath + "  # paste the content above",
			"# 2) load it (and every other sysctl.d file) into the running kernel:",
			"sudo sysctl --system",
			"# 3) re-run to confirm the numbers moved:",
			"posturescan scan",
		}
	}
	return plan
}

// Render returns the plan as the human-readable text the remediate command
// prints. It is deterministic given the plan.
func Render(p Plan) string {
	var b strings.Builder
	b.WriteString("posturescan remediate — DRY RUN (nothing was applied)\n\n")
	b.WriteString("=== drop-in file (NOT written) ===\n")
	fmt.Fprintf(&b, "# would be: %s\n", p.DropInPath)
	b.WriteString(p.DropInContent)
	b.WriteString("\n=== commands to run AFTER review (NOT executed) ===\n")
	if len(p.Commands) == 0 {
		b.WriteString("# none — host already matches the runtime-sysctl target\n")
	}
	for _, c := range p.Commands {
		b.WriteString(c + "\n")
	}
	if len(p.Notes) > 0 {
		b.WriteString("\n=== boot-time settings (cannot be set by a sysctl drop-in) ===\n")
		for _, n := range p.Notes {
			b.WriteString("# " + n + "\n")
		}
	}
	return b.String()
}
