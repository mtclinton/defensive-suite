package enumerate

import (
	"context"
	"errors"
	"testing"

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/runner"
)

// Sample bpftool JSON, trimmed to the fields the parser reads. Drawn from the
// shape `bpftool prog|map|link show -j` emits on a 6.x kernel.
const sampleProgJSON = `[
  {"id":12,"type":"tracepoint","name":"sys_enter","tag":"a1b2c3d4e5f60718","gpl_compatible":true,"attach_type":"trace_raw_tp","tracepoint":"sys_enter","pinned":["/sys/fs/bpf/sys_enter"]},
  {"id":34,"type":"kprobe","name":"","tag":"deadbeefcafef00d","gpl_compatible":false,"func":"__x64_sys_bpf","helpers":["bpf_probe_write_user","bpf_get_current_pid_tgid"]},
  {"id":7,"type":"xdp","name":"cil_from_netdev","tag":"0011223344556677","gpl_compatible":true,"attach_type":"xdp"}
]`

const sampleMapJSON = `[
  {"id":3,"type":"hash","name":"events"},
  {"id":4,"type":"array","name":"config","pinned":["/sys/fs/bpf/config"]}
]`

const sampleLinkJSON = `[
  {"id":1,"type":"tracing","prog_id":12,"attach_type":"trace_raw_tp","tp_name":"sys_enter"},
  {"id":2,"type":"xdp","prog_id":7,"devname":"eth0"}
]`

func TestParseProgramsFields(t *testing.T) {
	progs, err := ParsePrograms(sampleProgJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(progs) != 3 {
		t.Fatalf("got %d programs", len(progs))
	}
	// Find by id since ParsePrograms preserves input order (Enumerate sorts).
	byID := map[int]Program{}
	for _, p := range progs {
		byID[p.ID] = p
	}
	tp := byID[12]
	if tp.Name != "sys_enter" || tp.Type != "tracepoint" || tp.Tag != "a1b2c3d4e5f60718" {
		t.Errorf("tracepoint parsed wrong: %+v", tp)
	}
	if tp.AttachTo != "sys_enter" {
		t.Errorf("attach_to=%q want sys_enter", tp.AttachTo)
	}
	if len(tp.Pinned) != 1 || tp.Pinned[0] != "/sys/fs/bpf/sys_enter" {
		t.Errorf("pinned=%v", tp.Pinned)
	}
	kp := byID[34]
	if kp.Name != "" {
		t.Errorf("expected unnamed kprobe, got name=%q", kp.Name)
	}
	if kp.AttachTo != "__x64_sys_bpf" {
		t.Errorf("kprobe attach_to=%q (func fallback)", kp.AttachTo)
	}
	if len(kp.Helpers) != 2 || kp.Helpers[0] != "bpf_probe_write_user" {
		t.Errorf("kprobe helpers=%v", kp.Helpers)
	}
}

func TestParseEmptyAndNull(t *testing.T) {
	for _, in := range []string{"", "   \n", "[]", "null"} {
		progs, err := ParsePrograms(in)
		if err != nil {
			t.Fatalf("input %q: %v", in, err)
		}
		if len(progs) != 0 {
			t.Errorf("input %q: got %d, want 0", in, len(progs))
		}
	}
}

func TestParseMalformedJSON(t *testing.T) {
	if _, err := ParsePrograms(`[{"id":1,`); err == nil {
		t.Error("expected parse error on malformed JSON")
	}
}

func TestParseMapsAndLinks(t *testing.T) {
	maps, err := ParseMaps(sampleMapJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(maps) != 2 || maps[1].Name != "config" || len(maps[1].Pinned) != 1 {
		t.Errorf("maps=%+v", maps)
	}
	links, err := ParseLinks(sampleLinkJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 {
		t.Fatalf("links=%d", len(links))
	}
	if links[0].Target != "sys_enter" || links[0].ProgID != 12 {
		t.Errorf("link0=%+v", links[0])
	}
	if links[1].Target != "eth0" {
		t.Errorf("link1 target=%q want eth0", links[1].Target)
	}
}

func TestEnumerateHappyPathSorts(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"bpftool prog show -j": {Stdout: sampleProgJSON},
		"bpftool map show -j":  {Stdout: sampleMapJSON},
		"bpftool link show -j": {Stdout: sampleLinkJSON},
	}}
	inv, err := Enumerate(context.Background(), f, "bpftool")
	if err != nil {
		t.Fatal(err)
	}
	if inv.Source != "bpftool" {
		t.Errorf("source=%q", inv.Source)
	}
	if len(inv.Programs) != 3 {
		t.Fatalf("programs=%d", len(inv.Programs))
	}
	// Sorted by ID ascending: 7, 12, 34.
	if inv.Programs[0].ID != 7 || inv.Programs[1].ID != 12 || inv.Programs[2].ID != 34 {
		t.Errorf("not sorted by id: %d %d %d", inv.Programs[0].ID, inv.Programs[1].ID, inv.Programs[2].ID)
	}
	if len(inv.Maps) != 2 || len(inv.Links) != 2 {
		t.Errorf("maps=%d links=%d", len(inv.Maps), len(inv.Links))
	}
}

func TestEnumerateBPFToolMissing(t *testing.T) {
	f := &runner.Fake{} // every call returns ErrNotFound
	_, err := Enumerate(context.Background(), f, "bpftool")
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err=%v, want ErrUnavailable", err)
	}
}

func TestEnumerateNonZeroExit(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"bpftool prog show -j": {ExitCode: 255, Stderr: "Error: can't get next program"},
	}}
	_, err := Enumerate(context.Background(), f, "bpftool")
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err=%v, want ErrUnavailable", err)
	}
}

func TestEnumerateDefaultsBPFToolName(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"bpftool prog show -j": {Stdout: "[]"},
		"bpftool map show -j":  {Stdout: "[]"},
		"bpftool link show -j": {Stdout: "[]"},
	}}
	if _, err := Enumerate(context.Background(), f, ""); err != nil {
		t.Fatalf("empty bpftool path should default to 'bpftool': %v", err)
	}
	if f.Calls[0] != "bpftool prog show -j" {
		t.Errorf("first call=%q", f.Calls[0])
	}
}
