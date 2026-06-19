package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/baseline"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/enumerate"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/report"
)

// oobFixture is the exact interchange JSON forensics/oob_parser.py emits — the
// contract between the Python out-of-band parser and the Go diff ingest. If this
// shape drifts on either side, the divergence path silently breaks, so we pin it.
const oobFixture = `{
  "source": "oob",
  "programs": [
    {"id": 7, "name": "cil_from_netdev", "type": "xdp", "tag": "0011223344556677",
     "attach_type": "", "attach_to": "", "helpers": [], "pinned": [], "gpl_compatible": false},
    {"id": 99, "name": "", "type": "kprobe", "tag": "deadbeefcafef00d",
     "attach_type": "", "attach_to": "__x64_sys_bpf",
     "helpers": ["bpf_probe_write_user"], "pinned": [], "gpl_compatible": false}
  ],
  "maps": [],
  "links": []
}`

func TestLoadOOBFromFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oob.json")
	if err := os.WriteFile(p, []byte(oobFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := loadOOB(p)
	if err != nil {
		t.Fatalf("loadOOB: %v", err)
	}
	if inv.Source != "oob" {
		t.Errorf("source=%q", inv.Source)
	}
	if len(inv.Programs) != 2 {
		t.Fatalf("programs=%d", len(inv.Programs))
	}
	// Sorted by ID ascending after load.
	if inv.Programs[0].ID != 7 || inv.Programs[1].ID != 99 {
		t.Errorf("not sorted: %d %d", inv.Programs[0].ID, inv.Programs[1].ID)
	}
	hidden := inv.Programs[1]
	if hidden.Type != "kprobe" || hidden.AttachTo != "__x64_sys_bpf" {
		t.Errorf("kprobe parsed wrong: %+v", hidden)
	}
	if len(hidden.Helpers) != 1 || hidden.Helpers[0] != "bpf_probe_write_user" {
		t.Errorf("helpers=%v", hidden.Helpers)
	}
}

func TestLoadOOBDefaultsSource(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oob.json")
	// No "source" key — loadOOB must default it to "oob".
	if err := os.WriteFile(p, []byte(`{"programs":[{"id":1,"tag":"a"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := loadOOB(p)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Source != "oob" {
		t.Errorf("source default=%q, want oob", inv.Source)
	}
}

func TestLoadOOBMalformed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOOB(p); err == nil {
		t.Error("expected error on malformed OOB JSON")
	}
}

// TestOOBDivergenceEndToEnd proves the loaded OOB inventory drives the
// divergence finding: the live view (missing the hidden kprobe) vs the OOB view
// (which sees it) yields a Critical "hidden from live" finding.
func TestOOBDivergenceEndToEnd(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oob.json")
	if err := os.WriteFile(p, []byte(oobFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	oob, err := loadOOB(p)
	if err != nil {
		t.Fatal(err)
	}
	// Live view sees only the legitimate XDP program; the kprobe is hidden.
	live := enumerate.Inventory{Source: "bpftool", Programs: []enumerate.Program{
		{ID: 7, Name: "cil_from_netdev", Type: "xdp", Tag: "0011223344556677"},
	}}
	d := enumerate.DivergenceFromOOB(live, oob)
	if len(d.HiddenFromLive) != 1 || d.HiddenFromLive[0].Tag != "deadbeefcafef00d" {
		t.Fatalf("expected one hidden program, got %+v", d.HiddenFromLive)
	}
	fs := d.Findings()
	if len(fs) != 1 || fs[0].Check != "divergence" {
		t.Fatalf("findings=%+v", fs)
	}
}

// oobBothViewsFixture is an out-of-band inventory whose suspicious-helper program
// is ALSO visible in the live view (same tag). Divergence therefore reports
// nothing — this is precisely the case the program-set membership check misses.
const oobBothViewsFixture = `{
  "source": "oob",
  "programs": [
    {"id": 7, "name": "cil_from_netdev", "type": "xdp", "tag": "0011223344556677",
     "attach_type": "", "attach_to": "", "helpers": [], "pinned": [], "gpl_compatible": false},
    {"id": 12, "name": "trusted_probe", "type": "kprobe", "tag": "a1b2c3d4e5f60718",
     "attach_type": "", "attach_to": "do_sys_openat2",
     "helpers": ["bpf_get_current_pid_tgid", "bpf_probe_write_user"], "pinned": [], "gpl_compatible": false}
  ],
  "maps": [],
  "links": []
}`

// TestOOBHelperScanFlagsAllowlistedVisibleProgram is the regression test for the
// flagship "can't-be-lied-to" offline path: an OOB program present in BOTH the
// live and the out-of-band views, carrying bpf_probe_write_user, must produce a
// High "helpers" finding. Before the fix the OOB path ran only program-set
// divergence (which sees nothing here, since the program is visible live too),
// so the suspicious helper was reported clean offline. This mirrors exactly what
// cmdDiff now does for the OOB inventory.
func TestOOBHelperScanFlagsAllowlistedVisibleProgram(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oob.json")
	if err := os.WriteFile(p, []byte(oobBothViewsFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	oob, err := loadOOB(p)
	if err != nil {
		t.Fatal(err)
	}

	// Live view sees BOTH programs (same tags) — so divergence yields nothing.
	live := enumerate.Inventory{Source: "bpftool", Programs: []enumerate.Program{
		{ID: 7, Name: "cil_from_netdev", Type: "xdp", Tag: "0011223344556677"},
		{ID: 12, Name: "trusted_probe", Type: "kprobe", Tag: "a1b2c3d4e5f60718", AttachTo: "do_sys_openat2"},
	}}
	d := enumerate.DivergenceFromOOB(live, oob)
	if len(d.HiddenFromLive) != 0 || len(d.LiveOnly) != 0 {
		t.Fatalf("expected no divergence when both views agree, got %+v", d)
	}
	if len(d.Findings()) != 0 {
		t.Fatalf("divergence alone must report nothing here, got %+v", d.Findings())
	}

	suspicious := []string{"bpf_override_return", "bpf_probe_write_user", "bpf_send_signal"}
	helperFindings := baseline.ScanHelpers(oob, suspicious)
	high := 0
	for _, f := range helperFindings {
		if f.Check == "helpers" && f.Severity == report.SeverityHigh {
			high++
		}
	}
	if high != 1 {
		t.Fatalf("the OOB helper scan must flag the suspicious helper High, got %+v", helperFindings)
	}
}
