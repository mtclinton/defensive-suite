// Package caps audits systemd unit files and OCI/Podman container specs for
// dangerous Linux capabilities — CAP_SYS_ADMIN and CAP_BPF — granted to a
// workload that is not a legitimate eBPF tool. CAP_BPF (or CAP_SYS_ADMIN on
// older kernels) is exactly what an eBPF rootkit needs to load its programs;
// anything holding it that is not a known observability/security tool is flagged
// (DESIGN.md, THREAT_MODEL.md: the bpf() attack surface and container escape).
package caps

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
)

// dangerousCaps are the capabilities that grant (or are equivalent to) eBPF
// program loading and broad kernel access. The map value is the human reason.
var dangerousCaps = map[string]string{
	"CAP_BPF":        "loads eBPF programs — the eBPF-rootkit primitive",
	"CAP_SYS_ADMIN":  "near-root; grants bpf() on older kernels and container-escape surface",
	"CAP_SYS_MODULE": "loads kernel modules — unsigned rootkit module path",
	"CAP_SYS_PTRACE": "ptrace any process — credential theft / ssh-keysign-pwn class",
}

// Grant is one capability granted to one workload, located in a file.
type Grant struct {
	Workload string // unit name or container name
	Cap      string // normalized CAP_* name
	Source   string // "systemd" | "oci" | "podman"
	Path     string // file the grant was found in
}

// normalizeCap upper-cases and CAP_-prefixes a capability token. systemd unit
// AmbientCapabilities/CapabilityBoundingSet accept "CAP_BPF"; OCI specs list
// bare "CAP_BPF" too, but tooling sometimes emits lowercase "bpf".
func normalizeCap(tok string) string {
	tok = strings.ToUpper(strings.TrimSpace(tok))
	if tok == "" {
		return ""
	}
	if !strings.HasPrefix(tok, "CAP_") {
		tok = "CAP_" + tok
	}
	return tok
}

// IsLegit reports whether the workload name matches a configured legitimate eBPF
// tool (substring, case-insensitive). Those are allowed to hold CAP_BPF.
func IsLegit(workload string, legit []string) bool {
	w := strings.ToLower(workload)
	for _, l := range legit {
		l = strings.ToLower(strings.TrimSpace(l))
		if l != "" && strings.Contains(w, l) {
			return true
		}
	}
	return false
}

// systemdCapKeys are the unit directives that add capabilities to a service.
var systemdCapKeys = map[string]bool{
	"AmbientCapabilities":   true,
	"CapabilityBoundingSet": true,
}

// ParseUnitGrants extracts dangerous-capability grants from a systemd unit file.
// It reads AmbientCapabilities= / CapabilityBoundingSet= lines (the directives
// that actually hand a capability to the process), ignoring commented lines.
//
// A leading '~' INVERTS the list per systemd.exec(5): the set becomes "all
// capabilities EXCEPT the listed ones", and a bare '~' resets to the FULL set.
// So a '~'-prefixed value is NOT a removal — it implicitly grants every
// dangerous capability that is not named in the inverted list (a bare '~' grants
// them all). Treating '~' as a removal — the previous behavior — is the inverse
// of systemd semantics and lets `CapabilityBoundingSet=~CAP_NET_BIND_SERVICE`
// silently keep CAP_BPF/CAP_SYS_ADMIN/CAP_SYS_MODULE/CAP_SYS_PTRACE, bypassing
// the capability audit entirely. Pure over the content.
func ParseUnitGrants(unitName, content string) []Grant {
	var grants []Grant
	seen := map[string]bool{}
	add := func(c string) {
		if _, bad := dangerousCaps[c]; bad && !seen[c] {
			seen[c] = true
			grants = append(grants, Grant{Workload: unitName, Cap: c, Source: "systemd"})
		}
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if !systemdCapKeys[strings.TrimSpace(key)] {
			continue
		}
		val = strings.TrimSpace(val)
		if strings.HasPrefix(val, "~") {
			// Inverted set: everything EXCEPT the listed caps is included. Grant
			// every dangerous cap not named after the '~' (bare '~' grants all).
			excluded := map[string]bool{}
			for _, tok := range strings.Fields(strings.TrimPrefix(val, "~")) {
				if c := normalizeCap(tok); c != "" {
					excluded[c] = true
				}
			}
			for c := range dangerousCaps {
				if !excluded[c] {
					add(c)
				}
			}
			continue
		}
		for _, tok := range strings.Fields(val) {
			add(normalizeCap(tok))
		}
	}
	return grants
}

// AuditUnitDirs scans systemd unit directories for dangerous capability grants
// and returns findings. A grant by a legit eBPF tool is reported at Info; any
// other workload is High (a non-eBPF unit should not hold CAP_BPF/SYS_ADMIN).
func AuditUnitDirs(dirs []string, legit []string) []report.Finding {
	var findings []report.Finding
	scanned := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			b, err := readLimited(path, 1<<20)
			if err != nil {
				continue
			}
			scanned++
			for _, g := range ParseUnitGrants(e.Name(), string(b)) {
				g.Path = path
				findings = append(findings, grantFinding(g, legit))
			}
		}
	}
	if scanned == 0 && len(findings) == 0 {
		findings = append(findings, report.Finding{
			Check: "caps", Severity: report.SeverityInfo,
			Title: "no systemd unit files found to audit for capabilities",
		})
	}
	return findings
}

// grantFinding classifies one grant relative to the legit-tool allowlist.
func grantFinding(g Grant, legit []string) report.Finding {
	reason := dangerousCaps[g.Cap]
	if IsLegit(g.Workload, legit) {
		return report.Finding{
			Check: "caps", Severity: report.SeverityInfo, Path: g.Path,
			Title:  g.Cap + " granted to a known eBPF tool (allowed)",
			Detail: g.Source + " workload=" + g.Workload + " — " + reason,
		}
	}
	sev := report.SeverityHigh
	if g.Cap == "CAP_BPF" {
		sev = report.SeverityCritical // stray CAP_BPF is the rootkit primitive
	}
	return report.Finding{
		Check: "caps", Severity: sev, Path: g.Path,
		Title:     "stray " + g.Cap + " granted to a non-eBPF workload",
		Detail:    g.Source + " workload=" + g.Workload + " — " + reason,
		Technique: "T1068",
	}
}

// readLimited reads at most maxBytes from path. Unit/spec files are small; the
// bound guards against an attacker-redirected endless file.
func readLimited(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	var total int64
	for total < maxBytes {
		n, err := f.Read(tmp)
		buf = append(buf, tmp[:n]...)
		total += int64(n)
		if err != nil {
			break
		}
	}
	return buf, nil
}
