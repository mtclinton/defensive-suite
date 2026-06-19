// Package enumerate produces a normalized inventory of the BPF objects loaded on
// a host — programs, maps, and links — from the portable, kernel-light path:
// shelling out to `bpftool prog|map|link show -j` and parsing the JSON. This is
// the testable core. It deliberately avoids any cilium/ebpf dependency so the
// default build is stdlib-only and offline-green; the deeper, Linux-only direct
// enumeration lives behind the `linux && ebpf` build tag (see direct_ebpf.go).
//
// CAVEAT BY DESIGN: bpftool runs on the live, possibly-compromised kernel. A
// `sys_bpf`-hooking rootkit hides itself from exactly this view. That is why the
// inventory produced here is meant to be compared against an out-of-band view
// (an offline prog_idr walk) — the divergence, not this view alone, is the
// proof of an implant. See package baseline and DivergenceFromOOB.
package enumerate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/runner"
)

// Program is a normalized BPF program record. The JSON tags also define the
// out-of-band ("OOB") interchange shape that `bpfsentry diff` ingests, so a
// Volatility prog_idr walk emits the same structure.
type Program struct {
	ID         int      `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`        // tracepoint, kprobe, xdp, lsm, ...
	Tag        string   `json:"tag"`         // bpftool's 8-byte program tag
	AttachType string   `json:"attach_type"` // e.g. trace_fentry, lsm_mac
	AttachTo   string   `json:"attach_to"`   // resolved hook/symbol where known
	Helpers    []string `json:"helpers"`     // helper functions, when metadata exposes them
	Pinned     []string `json:"pinned"`      // bpffs pin paths
	GPL        bool     `json:"gpl_compatible"`
}

// Map is a normalized BPF map record.
type Map struct {
	ID     int      `json:"id"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Pinned []string `json:"pinned"`
}

// Link is a normalized BPF link record (a program attached to a hook).
type Link struct {
	ID         int    `json:"id"`
	Type       string `json:"type"`
	ProgID     int    `json:"prog_id"`
	AttachType string `json:"attach_type"`
	Target     string `json:"target"` // tracepoint name, cgroup path, ifname, ...
}

// Inventory is the full normalized view of the host's BPF state. Source records
// where the view came from ("bpftool" for the live path, "oob" for an offline
// memory walk) so a divergence comparison can label its two sides.
type Inventory struct {
	Source   string    `json:"source"`
	Programs []Program `json:"programs"`
	Maps     []Map     `json:"maps"`
	Links    []Link    `json:"links"`
}

// ErrUnavailable reports that the portable enumeration path could not run (no
// bpftool on PATH, or it failed). Callers surface this as an Info finding —
// "reduced visibility" — rather than treating it as a clean result.
var ErrUnavailable = errors.New("bpftool enumeration unavailable")

// Enumerate runs the three bpftool queries via r and assembles an Inventory.
// bpftoolPath may be a bare name (resolved on PATH) or an absolute path.
func Enumerate(ctx context.Context, r runner.Runner, bpftoolPath string) (Inventory, error) {
	if bpftoolPath == "" {
		bpftoolPath = "bpftool"
	}
	inv := Inventory{Source: "bpftool"}

	progRes, err := r.Run(ctx, bpftoolPath, "prog", "show", "-j")
	if err != nil {
		return inv, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if progRes.ExitCode != 0 {
		return inv, fmt.Errorf("%w: bpftool prog show exit=%d: %s", ErrUnavailable, progRes.ExitCode, progRes.Stderr)
	}
	inv.Programs, err = ParsePrograms(progRes.Stdout)
	if err != nil {
		return inv, fmt.Errorf("parse prog show: %w", err)
	}

	mapRes, err := r.Run(ctx, bpftoolPath, "map", "show", "-j")
	if err != nil {
		return inv, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	inv.Maps, err = ParseMaps(mapRes.Stdout)
	if err != nil {
		return inv, fmt.Errorf("parse map show: %w", err)
	}

	linkRes, err := r.Run(ctx, bpftoolPath, "link", "show", "-j")
	if err != nil {
		return inv, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	inv.Links, err = ParseLinks(linkRes.Stdout)
	if err != nil {
		return inv, fmt.Errorf("parse link show: %w", err)
	}

	inv.sort()
	return inv, nil
}

// rawProg mirrors the fields `bpftool prog show -j` emits that we care about.
// bpftool's JSON is not perfectly stable across versions, so unknown fields are
// ignored and missing ones default to zero values.
type rawProg struct {
	ID         int      `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Tag        string   `json:"tag"`
	AttachType string   `json:"attach_type"`
	GPL        bool     `json:"gpl_compatible"`
	Pinned     []string `json:"pinned"`
	// Some bpftool builds expose helpers under "map_ids"/"helpers"; we read the
	// optional "helpers" array when present (it appears with `prog show --json`
	// on kernels that surface used helpers via prog_info).
	Helpers []string `json:"helpers"`
	// Attach target shows up under different keys depending on program type.
	AttachTo   string `json:"attach_to"`
	Func       string `json:"func"` // kprobe/tracepoint symbol on some builds
	Tracepoint string `json:"tracepoint"`
}

// ParsePrograms parses `bpftool prog show -j` output (a JSON array) into the
// normalized Program slice. Empty/whitespace input is treated as an empty set.
func ParsePrograms(jsonOut string) ([]Program, error) {
	raw, err := decodeArray[rawProg](jsonOut)
	if err != nil {
		return nil, err
	}
	progs := make([]Program, 0, len(raw))
	for _, p := range raw {
		attachTo := firstNonEmpty(p.AttachTo, p.Func, p.Tracepoint)
		progs = append(progs, Program{
			ID:         p.ID,
			Name:       p.Name,
			Type:       p.Type,
			Tag:        p.Tag,
			AttachType: p.AttachType,
			AttachTo:   attachTo,
			Helpers:    p.Helpers,
			Pinned:     p.Pinned,
			GPL:        p.GPL,
		})
	}
	return progs, nil
}

type rawMap struct {
	ID     int      `json:"id"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Pinned []string `json:"pinned"`
}

// ParseMaps parses `bpftool map show -j` output into normalized Maps.
func ParseMaps(jsonOut string) ([]Map, error) {
	raw, err := decodeArray[rawMap](jsonOut)
	if err != nil {
		return nil, err
	}
	maps := make([]Map, 0, len(raw))
	for _, m := range raw {
		maps = append(maps, Map(m))
	}
	return maps, nil
}

type rawLink struct {
	ID         int    `json:"id"`
	Type       string `json:"type"`
	ProgID     int    `json:"prog_id"`
	AttachType string `json:"attach_type"`
	Target     string `json:"target"`
	TpName     string `json:"tp_name"`
	Cgroup     string `json:"cgroup_path"`
	Devname    string `json:"devname"`
}

// ParseLinks parses `bpftool link show -j` output into normalized Links.
func ParseLinks(jsonOut string) ([]Link, error) {
	raw, err := decodeArray[rawLink](jsonOut)
	if err != nil {
		return nil, err
	}
	links := make([]Link, 0, len(raw))
	for _, l := range raw {
		target := firstNonEmpty(l.Target, l.TpName, l.Cgroup, l.Devname)
		links = append(links, Link{
			ID:         l.ID,
			Type:       l.Type,
			ProgID:     l.ProgID,
			AttachType: l.AttachType,
			Target:     target,
		})
	}
	return links, nil
}

// decodeArray unmarshals a JSON array of T. bpftool emits an empty result as
// either "" (no output), "[]", or "null"; all map to an empty slice.
func decodeArray[T any](jsonOut string) ([]T, error) {
	if isBlank(jsonOut) {
		return nil, nil
	}
	var out []T
	if err := json.Unmarshal([]byte(jsonOut), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func isBlank(s string) bool {
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// sort orders the inventory by ID for stable output, diffing, and signatures.
func (inv *Inventory) sort() {
	sort.Slice(inv.Programs, func(i, j int) bool { return inv.Programs[i].ID < inv.Programs[j].ID })
	sort.Slice(inv.Maps, func(i, j int) bool { return inv.Maps[i].ID < inv.Maps[j].ID })
	sort.Slice(inv.Links, func(i, j int) bool { return inv.Links[i].ID < inv.Links[j].ID })
}

// Sort exposes the stable ordering for callers that build an Inventory from an
// out-of-band source (e.g. the forensics parser output ingested by `diff`).
func (inv *Inventory) Sort() { inv.sort() }
