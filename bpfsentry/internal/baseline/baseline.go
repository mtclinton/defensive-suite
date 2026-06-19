// Package baseline captures an early-boot allowlist of the BPF programs the host
// is expected to run — its real agents (Cilium, Tetragon, the suite's tracer,
// EDR) loaded before any third-party agent or implant — and diffs a later
// enumeration against it. The highest-signal finding is a program attached at a
// tracepoint/LSM/kprobe hook that is NOT in the allowlist, or an unnamed
// kretprobe/XDP program. It also flags programs whose metadata exposes
// suspicious helpers (bpf_override_return, bpf_probe_write_user, bpf_send_signal).
//
// The baseline file is the trust anchor: it must be captured at known-good state
// (early boot) and stored on read-only/off-host media. If it is writable on the
// box, a rootkit rewrites it and the diff is worthless. This mirrors authwatch's
// off-host hash baseline.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/enumerate"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/report"
)

// Entry is the recorded identity of one allowlisted program: enough to recognise
// the same program later without depending on the volatile kernel-assigned ID.
type Entry struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	AttachType string `json:"attach_type,omitempty"`
	AttachTo   string `json:"attach_to,omitempty"`
}

// Baseline is the early-boot allowlist plus a stable signature of the whole set.
type Baseline struct {
	Tool      string    `json:"tool"`
	Host      string    `json:"host"`
	Created   time.Time `json:"created"`
	Signature string    `json:"signature"` // sha256 over the sorted entry keys
	Entries   []Entry   `json:"entries"`
}

// entryKey is the stable identity used for allowlist membership and the
// signature. The tag (a hash of the instruction stream) is preferred; name+type
// is the fallback for tagless records.
func entryKey(name, typ, tag string) string {
	if tag != "" {
		return "tag:" + tag
	}
	return "nt:" + typ + "/" + name
}

func (e Entry) key() string { return entryKey(e.Name, e.Type, e.Tag) }

// Capture builds an allowlist from an enumeration taken at known-good state.
func Capture(host string, t time.Time, inv enumerate.Inventory) Baseline {
	b := Baseline{Tool: "bpfsentry", Host: host, Created: t}
	for _, p := range inv.Programs {
		b.Entries = append(b.Entries, Entry{
			Name:       p.Name,
			Type:       p.Type,
			Tag:        p.Tag,
			AttachType: p.AttachType,
			AttachTo:   p.AttachTo,
		})
	}
	sort.Slice(b.Entries, func(i, j int) bool { return b.Entries[i].key() < b.Entries[j].key() })
	b.Signature = signature(b.Entries)
	return b
}

// signature is a stable SHA-256 over the sorted entry keys. A changed signature
// is a one-line "the BPF program set is not what it was at boot" indicator.
func signature(entries []Entry) string {
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.key())
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Save writes the baseline as indented JSON with restrictive permissions.
func (b Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// Load reads a baseline from path.
func Load(path string) (Baseline, error) {
	var b Baseline
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, err
	}
	return b, nil
}

// allowSet is the membership set of an allowlist baseline.
func (b Baseline) allowSet() map[string]bool {
	set := make(map[string]bool, len(b.Entries))
	for _, e := range b.Entries {
		set[e.key()] = true
	}
	return set
}

// hookTypes are the program types where an unallowlisted attachment is the
// highest-signal indicator — these are the hooks rootkits use to intercept
// syscalls, hide files/processes, and override return values.
var hookTypes = map[string]bool{
	"kprobe":         true,
	"kretprobe":      true,
	"tracepoint":     true,
	"raw_tracepoint": true,
	"raw_tp":         true,
	"perf_event":     true,
	"lsm":            true,
	"lsm_mac":        true,
	"fentry":         true,
	"fexit":          true,
	"tracing":        true,
	"xdp":            true,
	"sched_cls":      true,
	"sched_act":      true,
	"cgroup_skb":     true,
	"sk_skb":         true,
}

func isHookType(t string) bool { return hookTypes[strings.ToLower(t)] }

// isUnnamed treats a blank or all-numeric/placeholder name as unnamed. Real
// agents name their programs; an unnamed kretprobe/XDP is a classic rootkit tell.
func isUnnamed(name string) bool {
	return strings.TrimSpace(name) == ""
}

// Diff compares a current enumeration against the allowlist baseline and a set
// of suspicious helper names. It is a pure function over its inputs — no I/O, no
// kernel — so it is fully table-testable.
//
// It flags, in order:
//   - signature drift (Medium, once): the set no longer matches the boot set;
//   - each program not in the allowlist, escalated to High when it is attached
//     at a hook type, with an extra bump for an unnamed kretprobe/XDP program;
//   - any program using a suspicious helper (High), allowlisted or not.
func Diff(base Baseline, inv enumerate.Inventory, suspiciousHelpers []string) []report.Finding {
	if len(base.Entries) == 0 {
		return []report.Finding{{
			Check: "baseline", Severity: report.SeverityInfo,
			Title: "early-boot allowlist is empty; capture one at known-good boot",
		}}
	}

	var findings []report.Finding
	allow := base.allowSet()
	susp := toSet(suspiciousHelpers)

	// Signature drift: one summary line if the overall set changed.
	cur := Capture(base.Host, base.Created, inv) // reuse Capture only for its signature
	if cur.Signature != base.Signature {
		findings = append(findings, report.Finding{
			Check: "baseline", Severity: report.SeverityMedium,
			Title:  "live BPF program set diverges from the early-boot allowlist",
			Detail: fmt.Sprintf("baseline signature=%s current=%s", short(base.Signature), short(cur.Signature)),
		})
	}

	for _, p := range inv.Programs {
		key := entryKey(p.Name, p.Type, p.Tag)
		if !allow[key] {
			findings = append(findings, unallowlistedFinding(p))
		}
	}

	// The suspicious-helper scan fires regardless of allowlist membership: even a
	// "trusted" program that gained an override/write-user helper is worth
	// surfacing. It is factored into ScanHelpers so cmdDiff can run the same scan
	// against the live AND the out-of-band inventories — an allowlisted,
	// live-visible program that carries a rootkit-primitive helper must be flagged
	// even on the offline (prog_idr) path.
	findings = append(findings, scanHelpers(inv, susp)...)
	return findings
}

// ScanHelpers flags every program in inv that uses one of the suspiciousHelpers
// (bpf_override_return / bpf_probe_write_user / bpf_send_signal and friends).
// Each match is a High "helpers" finding. It is a pure function over its inputs —
// no I/O, no kernel — so the identical scan runs against both the live bpftool
// view and the out-of-band (offline prog_idr) view, which carries helper metadata
// through forensics/oob_parser.py. This is the DESIGN-mandated suspicious-helper
// check on the can't-be-lied-to offline path.
func ScanHelpers(inv enumerate.Inventory, suspiciousHelpers []string) []report.Finding {
	return scanHelpers(inv, toSet(suspiciousHelpers))
}

func scanHelpers(inv enumerate.Inventory, susp map[string]bool) []report.Finding {
	if len(susp) == 0 {
		return nil
	}
	var findings []report.Finding
	for _, p := range inv.Programs {
		for _, h := range p.Helpers {
			if susp[h] {
				findings = append(findings, report.Finding{
					Check: "helpers", Severity: report.SeverityHigh,
					Title:     fmt.Sprintf("BPF program uses suspicious helper %s", h),
					Path:      describe(p),
					Detail:    fmt.Sprintf("type=%s tag=%s — write-to-user/override-return/send-signal helpers are rootkit primitives", p.Type, p.Tag),
					Technique: "T1014",
				})
			}
		}
	}
	return findings
}

func unallowlistedFinding(p enumerate.Program) report.Finding {
	sev := report.SeverityLow
	title := "BPF program not in the early-boot allowlist"
	tech := ""
	if isHookType(p.Type) {
		sev = report.SeverityHigh
		title = "unallowlisted BPF program attached at a kernel hook"
		tech = "T1014"
	}
	if isUnnamed(p.Name) && (strings.EqualFold(p.Type, "kretprobe") || strings.EqualFold(p.Type, "xdp")) {
		sev = report.SeverityCritical
		title = "unnamed kretprobe/XDP program not in the allowlist"
		tech = "T1014"
	}
	return report.Finding{
		Check: "baseline", Severity: sev,
		Title:     title,
		Path:      describe(p),
		Detail:    fmt.Sprintf("type=%s tag=%s attach=%s", p.Type, p.Tag, firstNonEmpty(p.AttachTo, p.AttachType)),
		Technique: tech,
	}
}

func describe(p enumerate.Program) string {
	name := p.Name
	if isUnnamed(name) {
		name = "<unnamed>"
	}
	if p.AttachTo != "" {
		return name + "@" + p.AttachTo
	}
	return name
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, i := range items {
		set[i] = true
	}
	return set
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
