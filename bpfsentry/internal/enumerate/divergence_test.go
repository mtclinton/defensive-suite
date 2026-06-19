package enumerate

import (
	"testing"

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/report"
)

func TestDivergenceHiddenImplant(t *testing.T) {
	live := Inventory{Source: "bpftool", Programs: []Program{
		{ID: 7, Name: "cil_from_netdev", Type: "xdp", Tag: "0011223344556677"},
		{ID: 12, Name: "sys_enter", Type: "tracepoint", Tag: "a1b2c3d4e5f60718"},
	}}
	// The out-of-band walk sees an extra kprobe the live kernel hides.
	oob := Inventory{Source: "oob", Programs: []Program{
		{ID: 7, Name: "cil_from_netdev", Type: "xdp", Tag: "0011223344556677"},
		{ID: 12, Name: "sys_enter", Type: "tracepoint", Tag: "a1b2c3d4e5f60718"},
		{ID: 99, Name: "", Type: "kprobe", Tag: "deadbeefcafef00d", AttachTo: "__x64_sys_bpf"},
	}}
	d := DivergenceFromOOB(live, oob)
	if len(d.HiddenFromLive) != 1 {
		t.Fatalf("hidden=%d, want 1", len(d.HiddenFromLive))
	}
	if d.HiddenFromLive[0].Tag != "deadbeefcafef00d" {
		t.Errorf("hidden prog=%+v", d.HiddenFromLive[0])
	}
	if len(d.LiveOnly) != 0 {
		t.Errorf("liveOnly=%v, want none", d.LiveOnly)
	}

	fs := d.Findings()
	if len(fs) != 1 || fs[0].Severity != report.SeverityCritical || fs[0].Technique != "T1014" {
		t.Fatalf("findings=%+v", fs)
	}
	if fs[0].Check != "divergence" {
		t.Errorf("check=%q", fs[0].Check)
	}
}

func TestDivergenceCleanWhenIdentical(t *testing.T) {
	progs := []Program{
		{ID: 7, Name: "cil_from_netdev", Type: "xdp", Tag: "0011223344556677"},
		{ID: 12, Name: "sys_enter", Type: "tracepoint", Tag: "a1b2c3d4e5f60718"},
	}
	live := Inventory{Source: "bpftool", Programs: progs}
	// Same programs but different IDs (IDs differ between live and memory image).
	oob := Inventory{Source: "oob", Programs: []Program{
		{ID: 101, Name: "cil_from_netdev", Type: "xdp", Tag: "0011223344556677"},
		{ID: 102, Name: "sys_enter", Type: "tracepoint", Tag: "a1b2c3d4e5f60718"},
	}}
	d := DivergenceFromOOB(live, oob)
	if len(d.HiddenFromLive) != 0 || len(d.LiveOnly) != 0 {
		t.Errorf("identical-by-tag sets should not diverge: %+v", d)
	}
	if len(d.Findings()) != 0 {
		t.Errorf("clean divergence should yield no findings")
	}
}

func TestDivergenceLiveOnlyIsLow(t *testing.T) {
	live := Inventory{Programs: []Program{
		{ID: 7, Tag: "aaaa", Name: "a"},
		{ID: 8, Tag: "bbbb", Name: "b"}, // loaded after the snapshot
	}}
	oob := Inventory{Programs: []Program{
		{ID: 7, Tag: "aaaa", Name: "a"},
	}}
	d := DivergenceFromOOB(live, oob)
	if len(d.HiddenFromLive) != 0 {
		t.Errorf("hidden=%v, want none", d.HiddenFromLive)
	}
	if len(d.LiveOnly) != 1 || d.LiveOnly[0].Tag != "bbbb" {
		t.Fatalf("liveOnly=%+v", d.LiveOnly)
	}
	fs := d.Findings()
	if len(fs) != 1 || fs[0].Severity != report.SeverityLow {
		t.Errorf("live-only finding should be Low: %+v", fs)
	}
}

func TestDivergenceFallsBackToNameTypeWithoutTag(t *testing.T) {
	// An OOB record without a tag must still match a live record by name+type.
	live := Inventory{Programs: []Program{{ID: 1, Name: "guard", Type: "lsm"}}}
	oob := Inventory{Programs: []Program{{ID: 50, Name: "guard", Type: "lsm"}}}
	d := DivergenceFromOOB(live, oob)
	if len(d.HiddenFromLive) != 0 || len(d.LiveOnly) != 0 {
		t.Errorf("name+type match should not diverge: %+v", d)
	}
}

func TestDivergenceMultipleHiddenSortedByID(t *testing.T) {
	live := Inventory{}
	oob := Inventory{Programs: []Program{
		{ID: 30, Tag: "c"}, {ID: 10, Tag: "a"}, {ID: 20, Tag: "b"},
	}}
	d := DivergenceFromOOB(live, oob)
	if len(d.HiddenFromLive) != 3 {
		t.Fatalf("hidden=%d", len(d.HiddenFromLive))
	}
	if d.HiddenFromLive[0].ID != 10 || d.HiddenFromLive[1].ID != 20 || d.HiddenFromLive[2].ID != 30 {
		t.Errorf("hidden not sorted by id: %+v", d.HiddenFromLive)
	}
}
