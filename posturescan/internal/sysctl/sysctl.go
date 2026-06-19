// Package sysctl reads the kernel hardening sysctls posturescan cares about and
// diffs them against a target profile, producing the per-key OK/DIFFERENT table
// and a hardening index. The read and diff are pure functions over an injected
// value source so tests never depend on the host kernel.
//
// Threats this answers (see DESIGN.md / THREAT_MODEL.md): kernel LPE +
// container escape (Copy Fail / DirtyDecrypt / Dirty Frag), ssh-keysign-pwn
// (the ptrace race, fixed by kernel.yama.ptrace_scope=2), and the whole bpf()
// attack surface (kernel.unprivileged_bpf_disabled).
package sysctl

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
)

// Status values for a sysctl row.
const (
	StatusOK        = "OK"
	StatusDifferent = "DIFFERENT"
	StatusUnknown   = "UNKNOWN" // key not readable on this host
)

// Target is one key/value the goal profile wants. AllowedValues lets a key be
// satisfied by any of several values (e.g. unprivileged_bpf_disabled wants 1 OR
// 2). Want is the single recommended value used in the drop-in and the table.
type Target struct {
	Key           string
	Want          string
	AllowedValues []string // if non-empty, any match is OK; otherwise Want must match
	Severity      report.Severity
	Comment       string
	Technique     string // MITRE ATT&CK ID for the drift finding
}

// GoalProfile is the built-in hardening target from DESIGN.md. The goal state is
// unprivileged_bpf_disabled=2, ptrace_scope=2, lockdown on, module-sig enforced.
func GoalProfile() []Target {
	return []Target{
		{
			Key: "kernel.unprivileged_bpf_disabled", Want: "2",
			AllowedValues: []string{"1", "2"}, Severity: report.SeverityHigh,
			Comment:   "unprivileged bpf() — the eBPF-rootkit attack surface; want 1 (disabled) or 2 (locked)",
			Technique: "T1068",
		},
		{
			Key: "kernel.yama.ptrace_scope", Want: "2",
			AllowedValues: []string{"2", "3"}, Severity: report.SeverityHigh,
			Comment:   "ptrace scope — the ssh-keysign-pwn race fix; want 2 (admin-only) or 3 (none)",
			Technique: "T1068",
		},
		{
			Key: "kernel.kptr_restrict", Want: "2",
			AllowedValues: []string{"1", "2"}, Severity: report.SeverityMedium,
			Comment:   "hide kernel pointers from unprivileged readers (KASLR/exploit aid)",
			Technique: "T1082",
		},
		{
			Key: "kernel.dmesg_restrict", Want: "1",
			Severity: report.SeverityMedium,
			Comment:  "restrict dmesg to privileged users (leaks kernel addresses/state)",
		},
		{
			Key: "kernel.modules_disabled", Want: "1",
			Severity: report.SeverityLow,
			Comment:  "no further module loads once set (optional; breaks late module loads)",
		},
		// module.sig_enforce is exposed as a module parameter, not under
		// /proc/sys; the reader special-cases it (see ReadModuleSigEnforce).
		{
			Key: "module.sig_enforce", Want: "1",
			Severity: report.SeverityMedium,
			Comment:  "kernel module signature enforcement (blocks unsigned rootkit modules)",
		},
	}
}

// Source returns the current value of a sysctl key, ok=false when absent.
type Source interface {
	Get(key string) (value string, ok bool)
}

// procSysSource reads keys from a /proc/sys-style directory tree, mapping the
// dotted key to a path (kernel.yama.ptrace_scope -> kernel/yama/ptrace_scope).
type procSysSource struct{ root string }

func (s procSysSource) Get(key string) (string, bool) {
	rel := strings.ReplaceAll(key, ".", string(filepath.Separator))
	b, err := os.ReadFile(filepath.Join(s.root, rel))
	if err != nil {
		return "", false
	}
	return normalize(string(b)), true
}

// mapSource is a pre-parsed key->value source (e.g. from `sysctl -a` output or a
// test fixture).
type mapSource map[string]string

func (m mapSource) Get(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

// chainSource tries each source in order, returning the first hit.
type chainSource []Source

func (c chainSource) Get(key string) (string, bool) {
	for _, s := range c {
		if v, ok := s.Get(key); ok {
			return v, true
		}
	}
	return "", false
}

// NewProcSysSource reads keys from a /proc/sys-style directory (the host's
// /proc/sys in production, a fixture dir in tests).
func NewProcSysSource(root string) Source { return procSysSource{root: root} }

// NewMapSource wraps a plain key->value map as a Source.
func NewMapSource(m map[string]string) Source { return mapSource(m) }

// Chain composes sources with first-hit-wins precedence: the proc-sys root is
// authoritative, with parsed `sysctl -a` output as the fallback.
func Chain(sources ...Source) Source { return chainSource(sources) }

// ParseSysctlA parses `sysctl -a` output ("key = value", one per line, blanks
// and comments skipped) into a value map. Pure and table-tested.
func ParseSysctlA(output string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		out[key] = normalize(v)
	}
	return out
}

// ParseLockdown extracts the active kernel lockdown mode from the
// /sys/kernel/security/lockdown content, e.g. "none [integrity] confidentiality"
// -> "integrity". Returns "" when no mode is bracketed.
func ParseLockdown(content string) string {
	content = strings.TrimSpace(content)
	open := strings.IndexByte(content, '[')
	closeIdx := strings.IndexByte(content, ']')
	if open < 0 || closeIdx < 0 || closeIdx <= open+1 {
		return ""
	}
	return content[open+1 : closeIdx]
}

// normalize collapses internal whitespace (sysctl renders tab-separated lists)
// to single spaces and trims the value.
func normalize(v string) string {
	return strings.Join(strings.Fields(v), " ")
}

// matches reports whether got satisfies the target (any AllowedValues, else Want).
func (t Target) matches(got string) bool {
	if len(t.AllowedValues) > 0 {
		for _, a := range t.AllowedValues {
			if got == a {
				return true
			}
		}
		return false
	}
	return got == t.Want
}

// Diff builds the per-key OK/DIFFERENT table for the targets against src. It is
// pure: every value comes from the injected Source. Rows are returned in profile
// order (stable for table tests and human output).
func Diff(targets []Target, src Source) []report.SysctlRow {
	rows := make([]report.SysctlRow, 0, len(targets))
	for _, t := range targets {
		row := report.SysctlRow{Key: t.Key, Want: t.Want, Comment: t.Comment}
		got, ok := src.Get(t.Key)
		switch {
		case !ok:
			row.Got = "(unset)"
			row.Status = StatusUnknown
		case t.matches(got):
			row.Got = got
			row.Status = StatusOK
		default:
			row.Got = got
			row.Status = StatusDifferent
		}
		rows = append(rows, row)
	}
	return rows
}

// Findings turns DIFFERENT/UNKNOWN rows into report findings at the target's
// severity. OK rows produce no finding. An unreadable key is reported at Low (it
// may be a kernel without that knob, not necessarily drift).
func Findings(targets []Target, rows []report.SysctlRow) []report.Finding {
	bySev := map[string]report.Severity{}
	tech := map[string]string{}
	for _, t := range targets {
		bySev[t.Key] = t.Severity
		tech[t.Key] = t.Technique
	}
	var findings []report.Finding
	for _, r := range rows {
		switch r.Status {
		case StatusDifferent:
			findings = append(findings, report.Finding{
				Check: "sysctl", Severity: bySev[r.Key], Path: r.Key,
				Title:     "sysctl differs from hardening target",
				Detail:    "want=" + r.Want + " got=" + r.Got + " — " + r.Comment,
				Technique: tech[r.Key],
			})
		case StatusUnknown:
			findings = append(findings, report.Finding{
				Check: "sysctl", Severity: report.SeverityLow, Path: r.Key,
				Title:  "sysctl not readable (knob absent or restricted)",
				Detail: "want=" + r.Want,
			})
		}
	}
	return findings
}

// HardeningIndex is the share of targets satisfied, 0-100. UNKNOWN counts as not
// satisfied (a knob we cannot confirm is hardened is treated as unhardened).
func HardeningIndex(rows []report.SysctlRow) int {
	if len(rows) == 0 {
		return 100
	}
	ok := 0
	for _, r := range rows {
		if r.Status == StatusOK {
			ok++
		}
	}
	return ok * 100 / len(rows)
}

// DiffKeys returns the keys whose status is DIFFERENT or UNKNOWN, sorted — the
// set the remediation drop-in must set. Used by the remediate command.
func DiffKeys(rows []report.SysctlRow) []string {
	var keys []string
	for _, r := range rows {
		if r.Status != StatusOK {
			keys = append(keys, r.Key)
		}
	}
	sort.Strings(keys)
	return keys
}
