package sysctl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
)

func TestParseSysctlA(t *testing.T) {
	out := `# a comment
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 2
net.ipv4.ip_forward = 0

kernel.kptr_restrict	=	2
malformed line without equals
 ; semicolon comment = ignored
`
	m := ParseSysctlA(out)
	if m["kernel.yama.ptrace_scope"] != "1" {
		t.Errorf("ptrace_scope=%q", m["kernel.yama.ptrace_scope"])
	}
	if m["kernel.kptr_restrict"] != "2" {
		t.Errorf("kptr_restrict=%q (whitespace not normalized)", m["kernel.kptr_restrict"])
	}
	if _, ok := m["malformed line without equals"]; ok {
		t.Error("malformed line should be skipped")
	}
	if len(m) != 4 {
		t.Errorf("want 4 keys, got %d: %v", len(m), m)
	}
}

func TestParseLockdown(t *testing.T) {
	cases := []struct{ in, want string }{
		{"none [integrity] confidentiality", "integrity"},
		{"none integrity [confidentiality]", "confidentiality"},
		{"[none] integrity confidentiality", "none"},
		{"none integrity confidentiality", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := ParseLockdown(c.in); got != c.want {
			t.Errorf("ParseLockdown(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestProcSysSourceReadsFixture(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "kernel", "yama", "ptrace_scope"), "2\n")
	mustWrite(t, filepath.Join(root, "kernel", "unprivileged_bpf_disabled"), "1\n")
	src := NewProcSysSource(root)
	if v, ok := src.Get("kernel.yama.ptrace_scope"); !ok || v != "2" {
		t.Errorf("ptrace_scope got=%q ok=%v", v, ok)
	}
	if _, ok := src.Get("kernel.kptr_restrict"); ok {
		t.Error("absent key should report ok=false")
	}
}

func TestChainFallsBackToSysctlA(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "kernel", "yama", "ptrace_scope"), "2")
	// proc-sys has ptrace_scope; the map (sysctl -a) supplies the rest.
	src := Chain(
		NewProcSysSource(root),
		NewMapSource(ParseSysctlA("kernel.yama.ptrace_scope = 0\nkernel.dmesg_restrict = 1")),
	)
	// proc-sys wins for ptrace_scope.
	if v, _ := src.Get("kernel.yama.ptrace_scope"); v != "2" {
		t.Errorf("proc-sys should win: %q", v)
	}
	// fallback supplies dmesg_restrict.
	if v, ok := src.Get("kernel.dmesg_restrict"); !ok || v != "1" {
		t.Errorf("fallback dmesg_restrict got=%q ok=%v", v, ok)
	}
}

func TestDiffStatuses(t *testing.T) {
	targets := GoalProfile()
	src := NewMapSource(map[string]string{
		"kernel.unprivileged_bpf_disabled": "1", // allowed (1 or 2) -> OK
		"kernel.yama.ptrace_scope":         "0", // -> DIFFERENT
		"kernel.kptr_restrict":             "2", // OK
		// dmesg_restrict, modules_disabled, module.sig_enforce absent -> UNKNOWN
	})
	rows := Diff(targets, src)
	byKey := map[string]report.SysctlRow{}
	for _, r := range rows {
		byKey[r.Key] = r
	}
	if byKey["kernel.unprivileged_bpf_disabled"].Status != StatusOK {
		t.Errorf("bpf disabled=1 should be OK (allowed values): %+v", byKey["kernel.unprivileged_bpf_disabled"])
	}
	if byKey["kernel.yama.ptrace_scope"].Status != StatusDifferent {
		t.Errorf("ptrace_scope=0 should be DIFFERENT: %+v", byKey["kernel.yama.ptrace_scope"])
	}
	if byKey["kernel.dmesg_restrict"].Status != StatusUnknown {
		t.Errorf("absent dmesg_restrict should be UNKNOWN: %+v", byKey["kernel.dmesg_restrict"])
	}
	// Rows must stay in profile order.
	if rows[0].Key != "kernel.unprivileged_bpf_disabled" {
		t.Errorf("rows not in profile order: %v", rows[0].Key)
	}
}

func TestFindingsOnlyForNonOK(t *testing.T) {
	targets := GoalProfile()
	src := NewMapSource(map[string]string{
		"kernel.unprivileged_bpf_disabled": "2",
		"kernel.yama.ptrace_scope":         "0",
		"kernel.kptr_restrict":             "2",
		"kernel.dmesg_restrict":            "1",
		"kernel.modules_disabled":          "1",
		"module.sig_enforce":               "1",
	})
	rows := Diff(targets, src)
	fs := Findings(targets, rows)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (ptrace_scope), got %d: %+v", len(fs), fs)
	}
	if fs[0].Path != "kernel.yama.ptrace_scope" || fs[0].Severity != report.SeverityHigh {
		t.Errorf("finding=%+v", fs[0])
	}
	if fs[0].Technique != "T1068" {
		t.Errorf("technique=%q", fs[0].Technique)
	}
}

func TestHardeningIndex(t *testing.T) {
	rows := []report.SysctlRow{
		{Status: StatusOK}, {Status: StatusOK}, {Status: StatusDifferent}, {Status: StatusUnknown},
	}
	if got := HardeningIndex(rows); got != 50 {
		t.Errorf("index=%d want 50", got)
	}
	if HardeningIndex(nil) != 100 {
		t.Error("empty rows should be 100 (nothing failing)")
	}
}

func TestDiffKeys(t *testing.T) {
	rows := []report.SysctlRow{
		{Key: "b", Status: StatusOK},
		{Key: "a", Status: StatusDifferent},
		{Key: "c", Status: StatusUnknown},
	}
	keys := DiffKeys(rows)
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "c" {
		t.Errorf("DiffKeys=%v", keys)
	}
}

func TestParseProfileAndApply(t *testing.T) {
	prof := ParseProfile("# target\nkernel.yama.ptrace_scope = 2\n; note\nkernel.dmesg_restrict=1\n")
	if prof["kernel.yama.ptrace_scope"] != "2" {
		t.Errorf("profile=%v", prof)
	}
	targets := ApplyProfile(GoalProfile(), prof)
	var pt Target
	for _, t2 := range targets {
		if t2.Key == "kernel.yama.ptrace_scope" {
			pt = t2
		}
	}
	// ApplyProfile overrides only Want; it KEEPS the built-in AllowedValues so a
	// stricter-than-target host still passes (it must not narrow to {Want}).
	if pt.Want != "2" {
		t.Errorf("Want override not applied: %+v", pt)
	}
	if len(pt.AllowedValues) != 2 || pt.AllowedValues[0] != "2" || pt.AllowedValues[1] != "3" {
		t.Errorf("AllowedValues must be kept, not narrowed: %+v", pt)
	}
}

// TestApplyProfileDoesNotFlagStricterHost is the regression for the profile
// narrowing bug: a profile pinning ptrace_scope=2 must still report OK for an
// observed value of 3 (stricter), and unprivileged_bpf_disabled=1 must still be
// OK when the profile pins 2 — otherwise a legitimately-hardened host fails.
func TestApplyProfileDoesNotFlagStricterHost(t *testing.T) {
	prof := ParseProfile("kernel.yama.ptrace_scope = 2\nkernel.unprivileged_bpf_disabled = 2\nkernel.kptr_restrict = 2\n")
	targets := ApplyProfile(GoalProfile(), prof)
	rows := Diff(targets, NewMapSource(map[string]string{
		"kernel.yama.ptrace_scope":         "3", // stricter than the pinned 2
		"kernel.unprivileged_bpf_disabled": "1", // also-accepted, below pinned 2
		"kernel.kptr_restrict":             "1", // also-accepted, below pinned 2
	}))
	for _, r := range rows {
		switch r.Key {
		case "kernel.yama.ptrace_scope", "kernel.unprivileged_bpf_disabled", "kernel.kptr_restrict":
			if r.Status != StatusOK {
				t.Errorf("%s=%s should be OK against a profile pinning a different accepted value, got %s", r.Key, r.Got, r.Status)
			}
		}
	}
}

func TestEvaluateLockdown(t *testing.T) {
	cases := []struct {
		mode       string
		supported  bool
		wantStatus string
		report     bool
		sev        report.Severity
	}{
		{"confidentiality", true, StatusOK, false, report.SeverityInfo},
		{"integrity", true, StatusDifferent, true, report.SeverityLow},
		{"none", true, StatusDifferent, true, report.SeverityMedium},
		{"", false, StatusUnknown, true, report.SeverityLow},
	}
	for _, c := range cases {
		row, f, reported := EvaluateLockdown(c.mode, c.supported)
		if row.Status != c.wantStatus {
			t.Errorf("mode=%q status=%q want %q", c.mode, row.Status, c.wantStatus)
		}
		if reported != c.report {
			t.Errorf("mode=%q reported=%v want %v", c.mode, reported, c.report)
		}
		if reported && f.Severity != c.sev {
			t.Errorf("mode=%q sev=%v want %v", c.mode, f.Severity, c.sev)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
