// Package baseline captures and diffs SHA-256 hashes of auth-critical files
// against a known-good snapshot stored off-host — the trust anchor. A hash
// change on sshd/pam/libc since the baseline is a high-confidence implant signal
// even when the package database itself has been tampered with. The baseline
// file must live on read-only/off-host media; if it is writable on the box it is
// worthless.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
)

// Entry is the recorded fingerprint of one file.
type Entry struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
}

// Baseline is a snapshot of auth-critical file fingerprints.
type Baseline struct {
	Tool    string           `json:"tool"`
	Host    string           `json:"host"`
	Created time.Time        `json:"created"`
	Entries map[string]Entry `json:"entries"`
}

// HashFile computes the SHA-256 fingerprint of a file.
func HashFile(path string) (Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Entry{}, err
	}
	return Entry{
		SHA256: hex.EncodeToString(h.Sum(nil)),
		Size:   info.Size(),
		Mode:   info.Mode().String(),
	}, nil
}

// Capture fingerprints every readable path into a new Baseline.
func Capture(host string, t time.Time, paths []string) Baseline {
	b := Baseline{Tool: "authwatch", Host: host, Created: t, Entries: map[string]Entry{}}
	for _, p := range paths {
		if e, err := HashFile(p); err == nil {
			b.Entries[p] = e
		}
	}
	return b
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

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// Diff compares the current on-disk state against the baseline. It checks every
// caller-supplied path AND every path in the baseline that the caller did not
// supply — otherwise an attacker who deletes or renames a baselined file (e.g. a
// pam_*.so that then drops out of the live glob) would escape the diff entirely.
func Diff(base Baseline, paths []string) []report.Finding {
	if len(base.Entries) == 0 {
		return []report.Finding{{
			Check: "baseline", Severity: report.SeverityInfo,
			Title: "off-host baseline is empty; hash diff skipped",
		}}
	}
	var findings []report.Finding
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		findings = append(findings, diffOne(base, p)...)
	}
	// Baselined paths the live scan no longer surfaces, in stable order.
	var dropped []string
	for bp := range base.Entries {
		if !seen[bp] {
			dropped = append(dropped, bp)
		}
	}
	sort.Strings(dropped)
	for _, bp := range dropped {
		findings = append(findings, diffOne(base, bp)...)
	}
	return findings
}

func diffOne(base Baseline, p string) []report.Finding {
	cur, err := HashFile(p)
	old, known := base.Entries[p]
	switch {
	case err != nil && known:
		return []report.Finding{{
			Check: "baseline", Severity: report.SeverityHigh, Path: p,
			Title:  "baselined auth file now missing or unreadable",
			Detail: err.Error(), Technique: "T1070.004",
		}}
	case err != nil && !known:
		// Absent and not baselined — nothing to say.
		return nil
	case !known:
		return []report.Finding{{
			Check: "baseline", Severity: report.SeverityLow, Path: p,
			Title:  "auth file present but absent from baseline",
			Detail: "capture a fresh baseline at known-good state to cover it",
		}}
	case cur.SHA256 != old.SHA256:
		return []report.Finding{{
			Check: "baseline", Severity: report.SeverityCritical, Path: p,
			Title:     "auth file changed since known-good baseline",
			Detail:    fmt.Sprintf("baseline=%s current=%s", short(old.SHA256), short(cur.SHA256)),
			Technique: "T1554",
		}}
	}
	return nil
}
