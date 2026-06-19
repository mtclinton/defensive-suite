// Package honeytoken is credsentinel's from-scratch honeytoken generator and
// tripwire — the clean, full-control alternative to canarytokens.com named in
// DESIGN.md. It plants decoy credentials exactly where a stealer looks (a fake
// AWS key block in ~/.aws/credentials.bak, a decoy kubeconfig, a fake ~/.env
// carrying a DNS-token hostname), records each decoy's path + content fingerprint
// + stat baseline in a manifest, and later detects a *trip*: a decoy whose access
// time advanced past the deployment baseline (something read it) or whose content
// changed. No legitimate process touches a decoy credential, so a trip is a
// near-zero-false-positive breach indicator → assume compromise.
//
// The decoy credentials are deliberately INVALID (RFC-5737 / example-domain
// values, an unroutable cluster endpoint) so that if one is ever exfiltrated and
// used, it fails closed and — for the ~/.env DNS token — the lookup itself fires
// the alert. Nothing here ever touches the operator's real ~/.aws/credentials
// etc.; the decoys sit at sibling/uncontested paths (.bak, decoy.kubeconfig, the
// usually-absent ~/.env that no real workstation credential lives in).
package honeytoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
)

// maxDecoyBytes bounds how much of any decoy file credsentinel will read. A decoy
// lives in the user-writable home, so an attacker can replace one with a symlink
// to /dev/zero (or a giant file) to OOM the scheduled watch and blind the
// tripwire. Every decoy this tool plants is well under 1 MiB, so reading past this
// is itself a tamper signal — never an unbounded read.
const maxDecoyBytes = 1 << 20 // 1 MiB

// Decoy is one planted honeytoken file.
type Decoy struct {
	// Name is a stable label for the decoy class.
	Name string `json:"name"`
	// RelPath is the decoy's path relative to the deployment directory.
	RelPath string `json:"rel_path"`
	// content is the file body written at deploy time (not serialized).
	content string
}

// Decoys is the canonical decoy set from DESIGN.md. CanaryHost, when non-empty,
// is woven into the .env decoy as a DNS-token hostname so resolving/exfiltrating
// it fires a self-hosted Canarytoken; with no host it falls back to a labelled
// example hostname (still a tripwire via atime, just without the DNS leg).
func Decoys(canaryHost string) []Decoy {
	if canaryHost == "" {
		canaryHost = "decoy-token.example.invalid"
	}
	return []Decoy{
		{
			Name:    "aws-credentials-bak",
			RelPath: ".aws/credentials.bak",
			content: awsDecoy(),
		},
		{
			Name:    "kubeconfig-decoy",
			RelPath: ".kube/decoy.kubeconfig",
			content: kubeDecoy(),
		},
		{
			Name:    "env-dns-token",
			RelPath: ".env",
			content: envDecoy(canaryHost),
		},
	}
}

// awsDecoy is a syntactically valid but INVALID AWS credentials block. The key id
// uses the AKIA prefix so a stealer's regex grabs it; the values are nonsense, so
// the credential is dead on arrival if ever used.
func awsDecoy() string {
	return "# rotated key kept for rollback — do not delete\n" +
		"[default]\n" +
		"aws_access_key_id = AKIAHONEYTOKENDECOY0\n" +
		"aws_secret_access_key = " + fakeSecret() + "\n" +
		"region = us-east-1\n"
}

func kubeDecoy() string {
	return "apiVersion: v1\n" +
		"kind: Config\n" +
		"clusters:\n" +
		"- cluster:\n" +
		"    # unroutable (RFC 5737 TEST-NET-1) — fails closed if ever used\n" +
		"    server: https://192.0.2.10:6443\n" +
		"  name: prod-decoy\n" +
		"contexts:\n" +
		"- context:\n" +
		"    cluster: prod-decoy\n" +
		"    user: deploy-bot\n" +
		"  name: prod-decoy\n" +
		"current-context: prod-decoy\n" +
		"users:\n" +
		"- name: deploy-bot\n" +
		"  user:\n" +
		"    token: " + fakeSecret() + "\n"
}

func envDecoy(canaryHost string) string {
	return "# service credentials\n" +
		"DATABASE_URL=postgres://deploy:" + fakeSecret() + "@" + canaryHost + ":5432/prod\n" +
		"API_BASE=https://" + canaryHost + "/v1\n" +
		"API_TOKEN=" + fakeSecret() + "\n"
}

// fakeSecret returns a random-looking but invalid token so each deployment's
// decoys are unique (their fingerprints differ) without ever embedding a real
// secret. Randomness failure falls back to a fixed marker — the decoy is still
// valid, just not unique.
func fakeSecret() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "DECOYDECOYDECOYDECOYDECOYDECOY00"
	}
	return "DECOY" + hex.EncodeToString(b)
}

// Record is the manifest entry for one deployed decoy: where it is, what it
// fingerprints to, and the stat baseline the watch compares against.
type Record struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	SHA256   string    `json:"sha256"`
	Size     int64     `json:"size"`
	Deployed time.Time `json:"deployed"`
	// BaselineATimeUnix / BaselineMTimeUnix are the access/modify times captured
	// immediately after writing the decoy. A later atime beyond this is a read; a
	// later mtime is a write. Stored as Unix nanos so the manifest is portable.
	BaselineATimeUnix int64 `json:"baseline_atime_unix"`
	BaselineMTimeUnix int64 `json:"baseline_mtime_unix"`
}

// Manifest is the full deployment record, written to the config's manifest path.
type Manifest struct {
	Tool      string    `json:"tool"`
	Host      string    `json:"host"`
	Created   time.Time `json:"created"`
	Decoys    []Record  `json:"decoys"`
	CanaryURL bool      `json:"canary_dns_token"` // whether a DNS token was woven in
}

func fingerprint(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// Deploy writes every decoy under dir, captures its fingerprint and stat
// baseline, and returns the manifest. It never overwrites a non-decoy file: if a
// target path already exists and is not a previously deployed decoy of the same
// name, that decoy is skipped with an error recorded by the caller via the
// returned skip list. Decoys are written 0600 so they look like the real
// credential files (and so a curious `cat` is the attacker, not a backup tool).
func Deploy(dir, host string, t time.Time, decoys []Decoy, canaryWoven bool) (Manifest, []error) {
	m := Manifest{Tool: "credsentinel", Host: host, Created: t, CanaryURL: canaryWoven}
	var errs []error
	for _, d := range decoys {
		full := filepath.Join(dir, d.RelPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			errs = append(errs, fmt.Errorf("%s: mkdir: %w", d.Name, err))
			continue
		}
		// O_EXCL makes the guarantee real: if a non-decoy (the operator's actual
		// file) already sits at this path, the create fails with EEXIST and we
		// SKIP it rather than clobbering real data. Decoys are 0600 so they look
		// like the real credential files.
		f, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if os.IsExist(err) {
				errs = append(errs, fmt.Errorf("%s: %s already exists; skipped (not overwriting a pre-existing file)", d.Name, full))
			} else {
				errs = append(errs, fmt.Errorf("%s: open: %w", d.Name, err))
			}
			continue
		}
		if _, err := f.WriteString(d.content); err != nil {
			f.Close()
			errs = append(errs, fmt.Errorf("%s: write: %w", d.Name, err))
			continue
		}
		if err := f.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: close: %w", d.Name, err))
			continue
		}
		info, err := os.Stat(full)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: stat: %w", d.Name, err))
			continue
		}
		at, mt := times(info)
		m.Decoys = append(m.Decoys, Record{
			Name:              d.Name,
			Path:              full,
			SHA256:            fingerprint(d.content),
			Size:              info.Size(),
			Deployed:          t,
			BaselineATimeUnix: at.UnixNano(),
			BaselineMTimeUnix: mt.UnixNano(),
		})
	}
	return m, errs
}

// SaveManifest writes the manifest as indented JSON with restrictive perms.
func SaveManifest(path string, m Manifest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// LoadManifest reads a manifest from path. The read is bounded: the manifest sits
// under the user-writable home, so an attacker who can point it at /dev/zero (or
// swell it) must not be able to OOM the watch. A real manifest is kilobytes;
// maxDecoyBytes (1 MiB) is ample headroom, and a manifest exceeding it surfaces as
// a parse error rather than an unbounded allocation.
func LoadManifest(path string) (Manifest, error) {
	var m Manifest
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxDecoyBytes))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	return m, nil
}

// CheckRecord evaluates one decoy against its baseline using a stat snapshot. It
// is a pure function (no filesystem access) so the trip logic is fully unit-
// testable: pass the live atime/mtime/sha/exists and get findings back.
//
//   - missing decoy            → High  (someone deleted the tripwire — tampering)
//   - content changed (sha)    → Critical (decoy was written to / replaced)
//   - atime advanced past base → Critical (decoy was READ — the trip)
//   - quiet                    → Info  ("deployed and quiet")
func CheckRecord(rec Record, exists bool, curATimeUnix, curMTimeUnix int64, curSHA string) report.Finding {
	if !exists {
		return report.Finding{
			Check: "honeytoken", Severity: report.SeverityHigh, Path: rec.Path,
			Title:     "honeytoken decoy missing — tripwire removed",
			Detail:    "decoy " + rec.Name + " is gone; redeploy and investigate",
			Technique: "T1070.004",
		}
	}
	if curSHA != "" && curSHA != rec.SHA256 {
		return report.Finding{
			Check: "honeytoken", Severity: report.SeverityCritical, Path: rec.Path,
			Title:     "honeytoken decoy MODIFIED — assume compromise",
			Detail:    "decoy " + rec.Name + " content changed since deployment",
			Technique: "T1552.001",
		}
	}
	if curATimeUnix > rec.BaselineATimeUnix {
		return report.Finding{
			Check: "honeytoken", Severity: report.SeverityCritical, Path: rec.Path,
			Title: "honeytoken TRIPPED — decoy credential was read; assume compromise",
			Detail: fmt.Sprintf("decoy %s atime advanced: baseline=%s read=%s",
				rec.Name, unixNanoStr(rec.BaselineATimeUnix), unixNanoStr(curATimeUnix)),
			Technique: "T1552.001",
		}
	}
	// mtime moving without sha change is unusual (touch -m); flag it low.
	if curMTimeUnix > rec.BaselineMTimeUnix {
		return report.Finding{
			Check: "honeytoken", Severity: report.SeverityLow, Path: rec.Path,
			Title:  "honeytoken decoy mtime advanced without content change",
			Detail: "decoy " + rec.Name + " was touched; review",
		}
	}
	return report.Finding{
		Check: "honeytoken", Severity: report.SeverityInfo, Path: rec.Path,
		Title: "honeytoken deployed and quiet",
	}
}

// Watch evaluates every decoy in the manifest against its live state on disk and
// returns one finding per decoy. Reading a decoy here would itself advance its
// atime and self-trip, so Watch hashes via a routine that does not bump atime
// where the OS allows, and reads the manifest baseline — the read of the decoy's
// own bytes for the sha check is unavoidable, so the sha is computed only when an
// atime trip is NOT already evident, keeping false self-trips out.
func Watch(m Manifest) []report.Finding {
	var findings []report.Finding
	for _, rec := range m.Decoys {
		info, err := os.Stat(rec.Path)
		if err != nil {
			findings = append(findings, CheckRecord(rec, false, 0, 0, ""))
			continue
		}
		// A decoy whose on-disk size now dwarfs the recorded baseline is itself a
		// tamper signal — and the thing that would let an attacker OOM the watch
		// (a swap for a symlink to /dev/zero / a giant file). Flag it Critical and
		// do NOT read its bytes: report from the stat alone.
		if oversizedDecoy(info.Size(), rec.Size) {
			findings = append(findings, report.Finding{
				Check: "honeytoken", Severity: report.SeverityCritical, Path: rec.Path,
				Title: "honeytoken decoy size ballooned — assume tampering",
				Detail: fmt.Sprintf("decoy %s grew from %d to %d bytes; not reading it (possible /dev/zero swap)",
					rec.Name, rec.Size, info.Size()),
				Technique: "T1552.001",
			})
			continue
		}
		at, mt := times(info)
		curA, curM := at.UnixNano(), mt.UnixNano()
		// Only hash (which would itself read the file) if atime has NOT already
		// tripped — once tripped we report without touching the bytes again.
		curSHA := ""
		if curA <= rec.BaselineATimeUnix {
			if h, herr := hashFileNoLeak(rec.Path); herr == nil {
				curSHA = h
			}
		}
		findings = append(findings, CheckRecord(rec, true, curA, curM, curSHA))
	}
	return findings
}

// oversizedDecoy reports whether the live size is implausibly larger than the
// recorded decoy size. Every decoy is a few hundred bytes; we allow generous
// slack (baseline + maxDecoyBytes) before treating the growth as tampering.
func oversizedDecoy(live, baseline int64) bool {
	return live > baseline+maxDecoyBytes
}

// hashFileNoLeak streams a bounded hash of a decoy and leaves its atime/mtime
// exactly as it found them. Two hostile-environment properties matter here:
//
//   - bounded read: io.LimitReader caps the read at maxDecoyBytes so a swapped-in
//     endless file (symlink to /dev/zero) can never OOM the scheduled watch.
//   - atime-neutral: credsentinel's OWN read of a decoy advances its access time,
//     and the trip signal *is* "atime advanced past baseline" — so without
//     restoring the times, every scheduled watch would self-trip a false
//     "TRIPPED — assume compromise". We snapshot atime+mtime before reading and
//     restore them with os.Chtimes immediately after, so only a *foreign* read
//     (the attacker) moves atime.
func hashFileNoLeak(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	at, mt := times(info)
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, io.LimitReader(f, maxDecoyBytes))
	closeErr := f.Close()
	// Restore the original access/modify times so our read does not self-trip the
	// atime tripwire. Best-effort: a failure here is not fatal to the hash, but we
	// surface it so a silently-failing restore (which would reintroduce the false
	// trip) does not go unnoticed.
	restoreErr := os.Chtimes(path, at, mt)
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if restoreErr != nil {
		return "", restoreErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func unixNanoStr(n int64) string {
	if n == 0 {
		return "0"
	}
	return time.Unix(0, n).UTC().Format(time.RFC3339Nano)
}

// SummaryFinding rolls up a watch into the DESIGN verdict line: "N honeytokens
// deployed and quiet" when none tripped.
func SummaryFinding(m Manifest, findings []report.Finding) report.Finding {
	tripped := 0
	for _, f := range findings {
		if f.Check == "honeytoken" && f.Severity >= report.SeverityMedium {
			tripped++
		}
	}
	if tripped == 0 {
		return report.Finding{
			Check: "honeytoken", Severity: report.SeverityInfo,
			Title:  fmt.Sprintf("%d honeytokens deployed and quiet", len(m.Decoys)),
			Detail: "no decoy was read or modified since deployment",
		}
	}
	return report.Finding{
		Check: "honeytoken", Severity: report.SeverityCritical,
		Title:  fmt.Sprintf("%d of %d honeytokens TRIPPED — assume compromise", tripped, len(m.Decoys)),
		Detail: "rotate every credential from a clean device and escalate to bpfsentry",
	}
}

// AuditdRules renders the auditd watch lines for the deployed decoy paths. These
// are SHIPPED for the operator to install (deploy/audit/) — credsentinel never
// loads them. A read of a decoy via auditd is a second, kernel-level trip signal
// independent of atime (which an attacker can mount noatime to defeat).
func AuditdRules(m Manifest) string {
	var b strings.Builder
	b.WriteString("## credsentinel — auditd watches for deployed honeytokens.\n")
	b.WriteString("## SHIPPED, NOT LOADED. Install after review (see deploy/README.md).\n")
	b.WriteString("## A read (-p r) of any decoy below is a near-zero-false-positive trip.\n\n")
	paths := make([]string, 0, len(m.Decoys))
	for _, rec := range m.Decoys {
		paths = append(paths, rec.Path)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintf(&b, "-w %s -p rwa -k credsentinel_honeytoken\n", p)
	}
	return b.String()
}
