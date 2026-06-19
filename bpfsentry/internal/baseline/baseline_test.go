package baseline

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/enumerate"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/report"
)

func goodBoot() enumerate.Inventory {
	return enumerate.Inventory{Source: "bpftool", Programs: []enumerate.Program{
		{ID: 7, Name: "cil_from_netdev", Type: "xdp", Tag: "0011223344556677"},
		{ID: 12, Name: "sys_enter_probe", Type: "tracepoint", Tag: "a1b2c3d4e5f60718", AttachTo: "sys_enter"},
	}}
}

var defaultHelpers = []string{"bpf_override_return", "bpf_probe_write_user", "bpf_send_signal"}

func worst(findings []report.Finding) report.Severity {
	w := report.SeverityInfo
	for _, f := range findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

func TestCaptureSignatureStable(t *testing.T) {
	b1 := Capture("h", time.Unix(0, 0), goodBoot())
	b2 := Capture("h2", time.Unix(100, 0), goodBoot()) // host/time differ, set identical
	if b1.Signature == "" {
		t.Fatal("empty signature")
	}
	if b1.Signature != b2.Signature {
		t.Errorf("signature should depend only on the program set, not host/time: %s vs %s", b1.Signature, b2.Signature)
	}
	if len(b1.Entries) != 2 {
		t.Errorf("entries=%d", len(b1.Entries))
	}
}

func TestCaptureSignatureChangesWithSet(t *testing.T) {
	b1 := Capture("h", time.Unix(0, 0), goodBoot())
	inv := goodBoot()
	inv.Programs = append(inv.Programs, enumerate.Program{ID: 99, Name: "x", Type: "kprobe", Tag: "ffff"})
	b2 := Capture("h", time.Unix(0, 0), inv)
	if b1.Signature == b2.Signature {
		t.Error("adding a program must change the signature")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "allowlist.json")
	b := Capture("h", time.Unix(0, 0), goodBoot())
	if err := b.Save(p); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Signature != b.Signature || len(loaded.Entries) != 2 {
		t.Errorf("round trip mismatch: %+v", loaded)
	}
}

func TestDiffCleanWhenUnchanged(t *testing.T) {
	base := Capture("h", time.Unix(0, 0), goodBoot())
	f := Diff(base, goodBoot(), defaultHelpers)
	if len(f) != 0 {
		t.Errorf("unchanged set should diff clean, got %+v", f)
	}
}

func TestDiffEmptyBaselineIsInfo(t *testing.T) {
	f := Diff(Baseline{}, goodBoot(), defaultHelpers)
	if len(f) != 1 || f[0].Severity != report.SeverityInfo {
		t.Errorf("empty baseline diff=%+v", f)
	}
}

func TestDiffUnallowlistedHookProgramIsHigh(t *testing.T) {
	base := Capture("h", time.Unix(0, 0), goodBoot())
	inv := goodBoot()
	// A named kprobe nobody allowlisted, attached at a syscall hook.
	inv.Programs = append(inv.Programs, enumerate.Program{
		ID: 50, Name: "spy", Type: "kprobe", Tag: "abc123", AttachTo: "__x64_sys_getdents64",
	})
	f := Diff(base, inv, defaultHelpers)
	high := 0
	for _, fd := range f {
		if fd.Severity == report.SeverityHigh && fd.Check == "baseline" {
			high++
		}
	}
	if high != 1 {
		t.Errorf("expected one High unallowlisted-hook finding, got %+v", f)
	}
	// Signature also drifted, so a Medium drift line is expected too.
	if worst(f) < report.SeverityHigh {
		t.Errorf("worst severity should be at least High: %v", worst(f))
	}
}

func TestDiffUnnamedKretprobeIsCritical(t *testing.T) {
	base := Capture("h", time.Unix(0, 0), goodBoot())
	inv := goodBoot()
	inv.Programs = append(inv.Programs, enumerate.Program{
		ID: 60, Name: "", Type: "kretprobe", Tag: "deadbeef", AttachTo: "__x64_sys_bpf",
	})
	f := Diff(base, inv, defaultHelpers)
	crit := 0
	for _, fd := range f {
		if fd.Severity == report.SeverityCritical {
			crit++
			if fd.Path == "" {
				t.Error("critical finding should carry a path")
			}
		}
	}
	if crit != 1 {
		t.Errorf("expected one Critical unnamed-kretprobe finding, got %+v", f)
	}
}

func TestDiffUnallowlistedNonHookIsLow(t *testing.T) {
	base := Capture("h", time.Unix(0, 0), goodBoot())
	inv := goodBoot()
	// A non-hook program type (e.g. socket filter style) is lower signal.
	inv.Programs = append(inv.Programs, enumerate.Program{
		ID: 70, Name: "thing", Type: "socket_filter", Tag: "aaaa",
	})
	f := Diff(base, inv, defaultHelpers)
	sawLow := false
	for _, fd := range f {
		if fd.Check == "baseline" && fd.Severity == report.SeverityLow {
			sawLow = true
		}
		if fd.Check == "baseline" && fd.Severity == report.SeverityHigh {
			t.Errorf("non-hook program should not be High: %+v", fd)
		}
	}
	if !sawLow {
		t.Errorf("expected a Low unallowlisted finding for a non-hook program, got %+v", f)
	}
}

func TestDiffSuspiciousHelperFiresEvenIfAllowlisted(t *testing.T) {
	// Allowlist a program, then have the live view show it using a bad helper.
	boot := enumerate.Inventory{Programs: []enumerate.Program{
		{ID: 1, Name: "trusted", Type: "kprobe", Tag: "t1", AttachTo: "do_sys_open"},
	}}
	base := Capture("h", time.Unix(0, 0), boot)
	live := enumerate.Inventory{Programs: []enumerate.Program{
		{ID: 1, Name: "trusted", Type: "kprobe", Tag: "t1", AttachTo: "do_sys_open",
			Helpers: []string{"bpf_get_current_pid_tgid", "bpf_probe_write_user"}},
	}}
	f := Diff(base, live, defaultHelpers)
	helperHigh := 0
	for _, fd := range f {
		if fd.Check == "helpers" && fd.Severity == report.SeverityHigh {
			helperHigh++
		}
	}
	if helperHigh != 1 {
		t.Errorf("suspicious helper on an allowlisted program should still fire High, got %+v", f)
	}
}

func TestScanHelpersFlagsSuspiciousAcrossInventory(t *testing.T) {
	// ScanHelpers is the helper scan factored out so it can run against the
	// out-of-band inventory directly (the can't-be-lied-to offline path), not just
	// the live view. A program carrying bpf_probe_write_user must be flagged High;
	// a clean program must not.
	oob := enumerate.Inventory{Source: "oob", Programs: []enumerate.Program{
		{ID: 7, Name: "cil_from_netdev", Type: "xdp", Tag: "0011223344556677"},
		{ID: 99, Name: "trusted", Type: "kprobe", Tag: "deadbeef", AttachTo: "__x64_sys_bpf",
			Helpers: []string{"bpf_get_current_pid_tgid", "bpf_probe_write_user"}},
	}}
	f := ScanHelpers(oob, defaultHelpers)
	if len(f) != 1 {
		t.Fatalf("expected exactly one helper finding, got %+v", f)
	}
	if f[0].Check != "helpers" || f[0].Severity != report.SeverityHigh {
		t.Errorf("helper finding wrong: %+v", f[0])
	}
	if f[0].Path == "" {
		t.Error("helper finding should carry a path identifying the program")
	}
}

func TestScanHelpersEmptyHelperSetIsNoop(t *testing.T) {
	oob := enumerate.Inventory{Programs: []enumerate.Program{
		{ID: 1, Name: "x", Type: "kprobe", Tag: "a", Helpers: []string{"bpf_probe_write_user"}},
	}}
	if f := ScanHelpers(oob, nil); len(f) != 0 {
		t.Errorf("no suspicious-helper list configured should yield no findings, got %+v", f)
	}
}

func TestDiffTagAllowsIDChange(t *testing.T) {
	// The kernel assigns different IDs across boots; matching is by tag, so the
	// same program with a new ID must NOT be flagged as unallowlisted.
	base := Capture("h", time.Unix(0, 0), goodBoot())
	inv := goodBoot()
	inv.Programs[0].ID = 9999
	inv.Programs[1].ID = 8888
	f := Diff(base, inv, defaultHelpers)
	if len(f) != 0 {
		t.Errorf("ID change with identical tags should diff clean, got %+v", f)
	}
}
