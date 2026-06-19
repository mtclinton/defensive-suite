package enumerate

import (
	"fmt"
	"sort"

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/report"
)

// Divergence is the result of comparing the live `bpftool` view of programs
// against an out-of-band (memory-dump prog_idr walk) view. The thesis: a program
// the offline walk sees but the live syscall view does not is a program the
// kernel is actively hiding — proof of a `sys_bpf`-hooking rootkit. The reverse
// (live-only) is lower-signal: usually a race (a program loaded after the
// snapshot) but recorded for completeness.
type Divergence struct {
	// HiddenFromLive: present out-of-band, absent live → confirmed implant.
	HiddenFromLive []Program `json:"hidden_from_live"`
	// LiveOnly: present live, absent out-of-band → likely a post-snapshot load.
	LiveOnly []Program `json:"live_only"`
}

// progKey identifies a program across two enumeration sources. IDs are not
// stable between a live view and a memory image, and a rootkit can spoof a
// name, but the program tag is a hash of the instruction stream and the only
// field that ties the same program across the two views. We fall back to
// name+type when a tag is absent so tagless OOB records still match.
func progKey(p Program) string {
	if p.Tag != "" {
		return "tag:" + p.Tag
	}
	return fmt.Sprintf("nt:%s/%s", p.Type, p.Name)
}

// DivergenceFromOOB compares a live inventory against an out-of-band inventory
// and returns the set difference in both directions. It is a pure function over
// the two inventories — no I/O, no kernel — so it is fully table-testable. This
// is the function that turns "two enumerations" into "proof of a hidden
// implant".
func DivergenceFromOOB(live, oob Inventory) Divergence {
	liveByKey := make(map[string]bool, len(live.Programs))
	for _, p := range live.Programs {
		liveByKey[progKey(p)] = true
	}
	oobByKey := make(map[string]bool, len(oob.Programs))
	for _, p := range oob.Programs {
		oobByKey[progKey(p)] = true
	}

	var d Divergence
	for _, p := range oob.Programs {
		if !liveByKey[progKey(p)] {
			d.HiddenFromLive = append(d.HiddenFromLive, p)
		}
	}
	for _, p := range live.Programs {
		if !oobByKey[progKey(p)] {
			d.LiveOnly = append(d.LiveOnly, p)
		}
	}
	sort.Slice(d.HiddenFromLive, func(i, j int) bool { return d.HiddenFromLive[i].ID < d.HiddenFromLive[j].ID })
	sort.Slice(d.LiveOnly, func(i, j int) bool { return d.LiveOnly[i].ID < d.LiveOnly[j].ID })
	return d
}

// Findings renders a Divergence as report findings. A program hidden from the
// live view is the single highest-signal indicator in the whole suite: a
// confirmed kernel-resident implant → reinstall, do not clean.
func (d Divergence) Findings() []report.Finding {
	var findings []report.Finding
	for _, p := range d.HiddenFromLive {
		findings = append(findings, report.Finding{
			Check:     "divergence",
			Severity:  report.SeverityCritical,
			Title:     "BPF program visible out-of-band but hidden from the live kernel",
			Path:      describeProg(p),
			Detail:    fmt.Sprintf("tag=%s type=%s — the live sys_bpf view is lying; confirmed sys_bpf-hooking rootkit. Reinstall, do not clean.", p.Tag, p.Type),
			Technique: "T1014",
		})
	}
	for _, p := range d.LiveOnly {
		findings = append(findings, report.Finding{
			Check:    "divergence",
			Severity: report.SeverityLow,
			Title:    "BPF program present live but absent from the out-of-band snapshot",
			Path:     describeProg(p),
			Detail:   "usually a program loaded after the memory snapshot was taken; confirm against load-time alerting (Tetragon)",
		})
	}
	return findings
}

func describeProg(p Program) string {
	name := p.Name
	if name == "" {
		name = "<unnamed>"
	}
	if p.AttachTo != "" {
		return fmt.Sprintf("%s@%s", name, p.AttachTo)
	}
	return name
}
