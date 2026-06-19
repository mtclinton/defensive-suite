package honeytoken

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
)

func TestDecoysAreInvalidCredentials(t *testing.T) {
	ds := Decoys("")
	if len(ds) != 3 {
		t.Fatalf("expected 3 decoys, got %d", len(ds))
	}
	byName := map[string]Decoy{}
	for _, d := range ds {
		byName[d.Name] = d
	}
	// AWS decoy must carry an AKIA-prefixed but clearly-decoy key.
	aws := byName["aws-credentials-bak"].content
	if !strings.Contains(aws, "AKIAHONEYTOKENDECOY0") {
		t.Error("aws decoy missing the decoy access key id")
	}
	if !strings.HasSuffix(byName["aws-credentials-bak"].RelPath, ".aws/credentials.bak") {
		t.Errorf("aws decoy path=%q", byName["aws-credentials-bak"].RelPath)
	}
	// kube decoy must point at an unroutable TEST-NET server.
	if !strings.Contains(byName["kubeconfig-decoy"].content, "192.0.2.10") {
		t.Error("kube decoy should use RFC 5737 TEST-NET server")
	}
}

func TestEnvDecoyWeavesCanaryHost(t *testing.T) {
	ds := Decoys("abc123.canary.internal")
	var env string
	for _, d := range ds {
		if d.Name == "env-dns-token" {
			env = d.content
		}
	}
	if !strings.Contains(env, "abc123.canary.internal") {
		t.Error("env decoy did not weave in the canary host")
	}
}

func TestEnvDecoyDefaultHostWhenBlank(t *testing.T) {
	ds := Decoys("")
	for _, d := range ds {
		if d.Name == "env-dns-token" && !strings.Contains(d.content, "example.invalid") {
			t.Error("blank canary host should fall back to an example hostname")
		}
	}
}

func TestDeployWritesDecoysAndManifest(t *testing.T) {
	dir := t.TempDir() // NEVER the real home
	m, errs := Deploy(dir, "testhost", time.Now(), Decoys(""), false)
	if len(errs) != 0 {
		t.Fatalf("deploy errors: %v", errs)
	}
	if len(m.Decoys) != 3 {
		t.Fatalf("expected 3 records, got %d", len(m.Decoys))
	}
	for _, rec := range m.Decoys {
		if _, err := os.Stat(rec.Path); err != nil {
			t.Errorf("decoy %s not written: %v", rec.Name, err)
		}
		if rec.SHA256 == "" || rec.Size == 0 {
			t.Errorf("record missing fingerprint: %+v", rec)
		}
		// Decoys must be 0600 so they look like real credential files.
		info, _ := os.Stat(rec.Path)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("decoy %s perm=%v, want 0600", rec.Name, info.Mode().Perm())
		}
	}
}

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m, _ := Deploy(dir, "h", time.Now(), Decoys(""), true)
	mp := filepath.Join(dir, "manifest.json")
	if err := SaveManifest(mp, m); err != nil {
		t.Fatal(err)
	}
	got, err := LoadManifest(mp)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Decoys) != len(m.Decoys) || got.Decoys[0].SHA256 != m.Decoys[0].SHA256 {
		t.Errorf("round trip mismatch")
	}
	if !got.CanaryURL {
		t.Error("canary flag lost in round trip")
	}
}

func TestCheckRecordQuiet(t *testing.T) {
	rec := Record{Name: "x", Path: "/p", SHA256: "abc", BaselineATimeUnix: 100, BaselineMTimeUnix: 100}
	f := CheckRecord(rec, true, 100, 100, "abc")
	if f.Severity != report.SeverityInfo {
		t.Errorf("quiet decoy should be Info: %+v", f)
	}
}

func TestCheckRecordAtimeTrip(t *testing.T) {
	rec := Record{Name: "x", Path: "/p", SHA256: "abc", BaselineATimeUnix: 100, BaselineMTimeUnix: 100}
	f := CheckRecord(rec, true, 200, 100, "abc")
	if f.Severity != report.SeverityCritical {
		t.Fatalf("atime advance should be Critical: %+v", f)
	}
	if !strings.Contains(strings.ToLower(f.Title), "tripped") {
		t.Errorf("title=%q", f.Title)
	}
}

func TestCheckRecordContentChange(t *testing.T) {
	rec := Record{Name: "x", Path: "/p", SHA256: "abc", BaselineATimeUnix: 100, BaselineMTimeUnix: 100}
	f := CheckRecord(rec, true, 100, 100, "different")
	if f.Severity != report.SeverityCritical {
		t.Errorf("content change should be Critical: %+v", f)
	}
}

func TestCheckRecordMissing(t *testing.T) {
	rec := Record{Name: "x", Path: "/p"}
	f := CheckRecord(rec, false, 0, 0, "")
	if f.Severity != report.SeverityHigh {
		t.Errorf("missing decoy should be High: %+v", f)
	}
}

func TestWatchQuietAfterDeploy(t *testing.T) {
	dir := t.TempDir()
	m, _ := Deploy(dir, "h", time.Now(), Decoys(""), false)
	findings := Watch(m)
	for _, f := range findings {
		if f.Severity >= report.SeverityMedium {
			t.Errorf("freshly deployed decoys should be quiet, got: %+v", f)
		}
	}
}

func TestWatchDetectsContentChange(t *testing.T) {
	dir := t.TempDir()
	m, _ := Deploy(dir, "h", time.Now(), Decoys(""), false)
	// Overwrite one decoy's content; Watch must flag it Critical.
	tamper := m.Decoys[0].Path
	if err := os.WriteFile(tamper, []byte("attacker-was-here"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := Watch(m)
	found := false
	for _, f := range findings {
		if f.Path == tamper && f.Severity == report.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("watch did not flag the tampered decoy: %+v", findings)
	}
}

func TestWatchDetectsMissingDecoy(t *testing.T) {
	dir := t.TempDir()
	m, _ := Deploy(dir, "h", time.Now(), Decoys(""), false)
	if err := os.Remove(m.Decoys[1].Path); err != nil {
		t.Fatal(err)
	}
	findings := Watch(m)
	found := false
	for _, f := range findings {
		if f.Path == m.Decoys[1].Path && f.Severity == report.SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("watch did not flag the removed decoy: %+v", findings)
	}
}

func TestSummaryFindingQuiet(t *testing.T) {
	m := Manifest{Decoys: []Record{{}, {}, {}}}
	quiet := []report.Finding{
		{Check: "honeytoken", Severity: report.SeverityInfo},
		{Check: "honeytoken", Severity: report.SeverityInfo},
		{Check: "honeytoken", Severity: report.SeverityInfo},
	}
	s := SummaryFinding(m, quiet)
	if s.Severity != report.SeverityInfo || !strings.Contains(s.Title, "3 honeytokens deployed and quiet") {
		t.Errorf("summary=%+v", s)
	}
}

func TestSummaryFindingTripped(t *testing.T) {
	m := Manifest{Decoys: []Record{{}, {}, {}}}
	tripped := []report.Finding{
		{Check: "honeytoken", Severity: report.SeverityCritical},
		{Check: "honeytoken", Severity: report.SeverityInfo},
		{Check: "honeytoken", Severity: report.SeverityInfo},
	}
	s := SummaryFinding(m, tripped)
	if s.Severity != report.SeverityCritical || !strings.Contains(s.Title, "TRIPPED") {
		t.Errorf("summary=%+v", s)
	}
}

func TestAuditdRulesCoversDecoys(t *testing.T) {
	dir := t.TempDir()
	m, _ := Deploy(dir, "h", time.Now(), Decoys(""), false)
	rules := AuditdRules(m)
	for _, rec := range m.Decoys {
		if !strings.Contains(rules, rec.Path) {
			t.Errorf("auditd rules missing decoy path %s", rec.Path)
		}
	}
	if !strings.Contains(rules, "credsentinel_honeytoken") {
		t.Error("auditd rules missing the key")
	}
	if !strings.Contains(rules, "NOT LOADED") {
		t.Error("auditd rules should be labelled as not loaded")
	}
}

func TestFakeSecretIsUnique(t *testing.T) {
	a, b := fakeSecret(), fakeSecret()
	if a == b {
		t.Error("fake secrets should be unique per call")
	}
	if !strings.HasPrefix(a, "DECOY") {
		t.Errorf("fake secret should be labelled: %q", a)
	}
}

// FIX #4: the env-dns-token decoy must sit at a realistic read location (~/.env)
// that an in-scope stealer actually reads, not the inert ~/.config/app/.env.decoy.
func TestEnvDecoyPlantedAtRealisticReadPath(t *testing.T) {
	for _, d := range Decoys("") {
		if d.Name == "env-dns-token" {
			if d.RelPath != ".env" {
				t.Errorf("env-dns-token decoy RelPath=%q, want \".env\" (a path stealers read)", d.RelPath)
			}
			return
		}
	}
	t.Fatal("env-dns-token decoy not found")
}

// FIX #2 (the headline false-positive): Watch's own read advances atime, which is
// the trip signal. Deploy then Watch TWICE — the second Watch must still be quiet.
// Without the os.Chtimes atime restore in hashFileNoLeak, the first Watch's read
// bumps atime past the baseline and the second Watch falsely fires Critical
// "TRIPPED — assume compromise" (the scan service runs 4x/day).
func TestWatchTwiceStaysQuiet(t *testing.T) {
	dir := t.TempDir()
	m, errs := Deploy(dir, "h", time.Now(), Decoys(""), false)
	if len(errs) != 0 {
		t.Fatalf("deploy errors: %v", errs)
	}

	first := Watch(m)
	for _, f := range first {
		if f.Severity >= report.SeverityMedium {
			t.Fatalf("first watch should be quiet, got: %+v", f)
		}
	}

	second := Watch(m)
	for _, f := range second {
		if f.Severity >= report.SeverityMedium {
			t.Errorf("second watch self-tripped (atime not restored): %+v", f)
		}
		if strings.Contains(strings.ToLower(f.Title), "tripped") {
			t.Errorf("second watch reported a TRIP without any foreign read: %+v", f)
		}
	}
}

// FIX #2 corollary: a genuine foreign read (atime advancing past baseline) must
// still trip, proving the restore only neutralizes credsentinel's OWN read.
func TestWatchDetectsForeignRead(t *testing.T) {
	dir := t.TempDir()
	m, _ := Deploy(dir, "h", time.Now(), Decoys(""), false)
	// Simulate an attacker read by advancing atime past the recorded baseline.
	target := m.Decoys[0].Path
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(target, future, time.Unix(0, m.Decoys[0].BaselineMTimeUnix)); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range Watch(m) {
		if f.Path == target && f.Severity == report.SeverityCritical &&
			strings.Contains(strings.ToLower(f.Title), "tripped") {
			found = true
		}
	}
	if !found {
		t.Errorf("a foreign atime advance must still trip the watch: %+v", Watch(m))
	}
}

// FIX #1: an attacker can swap a decoy for a symlink to /dev/zero / a giant file
// to OOM the scheduled watch (an unbounded os.ReadFile), blinding the tripwire.
// Watch must treat a decoy whose size dwarfs the recorded baseline as a tamper
// FINDING and must NOT read its bytes.
func TestWatchOversizedDecoyIsTamperFindingNotOOM(t *testing.T) {
	dir := t.TempDir()
	m, _ := Deploy(dir, "h", time.Now(), Decoys(""), false)
	target := m.Decoys[0].Path
	// Replace the decoy with a file far larger than the recorded baseline + slack.
	huge := make([]byte, maxDecoyBytes+(1<<20)+512)
	if err := os.WriteFile(target, huge, 0o600); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range Watch(m) {
		if f.Path == target && f.Severity == report.SeverityCritical &&
			strings.Contains(strings.ToLower(f.Title), "size") {
			found = true
		}
	}
	if !found {
		t.Errorf("oversized decoy should be flagged Critical as tampering: %+v", Watch(m))
	}
}

// FIX #1 (hash path bound): hashFileNoLeak must cap its read at maxDecoyBytes so a
// merely-large (but not oversize-flagged) read can never be unbounded.
func TestHashFileNoLeakIsBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decoy")
	big := make([]byte, maxDecoyBytes+4096)
	for i := range big {
		big[i] = 'A'
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := hashFileNoLeak(path)
	if err != nil {
		t.Fatal(err)
	}
	// The hash must equal the hash of exactly the first maxDecoyBytes — proving the
	// read was bounded, not the whole file.
	want := fingerprint(string(big[:maxDecoyBytes]))
	if got != want {
		t.Errorf("hashFileNoLeak did not bound its read to maxDecoyBytes")
	}
}

// FIX #1 / #2: hashFileNoLeak must leave atime/mtime exactly as it found them.
func TestHashFileNoLeakRestoresTimes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decoy")
	if err := os.WriteFile(path, []byte("secret-decoy"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeA, beforeM := times(before)
	if _, err := hashFileNoLeak(path); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	afterA, afterM := times(after)
	if !afterA.Equal(beforeA) {
		t.Errorf("atime moved: before=%v after=%v (would self-trip the watch)", beforeA, afterA)
	}
	if !afterM.Equal(beforeM) {
		t.Errorf("mtime moved: before=%v after=%v", beforeM, afterM)
	}
}

// FIX #1: LoadManifest must bound its read so a manifest swapped for /dev/zero
// cannot OOM the watch. A manifest larger than maxDecoyBytes truncates and fails
// to parse rather than allocating unboundedly.
func TestLoadManifestIsBounded(t *testing.T) {
	dir := t.TempDir()
	mp := filepath.Join(dir, "manifest.json")
	// Write a valid JSON opening followed by padding past the cap; the bounded
	// read truncates mid-document so json.Unmarshal returns an error (not OOM).
	var b strings.Builder
	b.WriteString(`{"tool":"credsentinel","decoys":[`)
	b.WriteString(strings.Repeat(" ", maxDecoyBytes+1024))
	b.WriteString("]}")
	if err := os.WriteFile(mp, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(mp); err == nil {
		t.Error("an over-cap manifest should fail to parse (bounded read), not load successfully")
	}
}

// FIX #3: Deploy promises it never overwrites a non-decoy file. A pre-existing
// real file at a decoy path must be PRESERVED and the skip reported as an error.
func TestDeployNeverOverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	// Plant a "real" file exactly where the aws decoy would go.
	awsPath := filepath.Join(dir, ".aws", "credentials.bak")
	if err := os.MkdirAll(filepath.Dir(awsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	const realContent = "REAL-OPERATOR-DATA-do-not-clobber"
	if err := os.WriteFile(awsPath, []byte(realContent), 0o600); err != nil {
		t.Fatal(err)
	}

	m, errs := Deploy(dir, "h", time.Now(), Decoys(""), false)

	// The real file must be byte-for-byte preserved.
	got, err := os.ReadFile(awsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != realContent {
		t.Errorf("Deploy clobbered a pre-existing file: got %q", string(got))
	}

	// The aws decoy must NOT be in the manifest (it was skipped).
	for _, rec := range m.Decoys {
		if rec.Path == awsPath {
			t.Errorf("skipped decoy must not appear in the manifest: %+v", rec)
		}
	}

	// The skip must be reported as an error mentioning the path.
	reported := false
	for _, e := range errs {
		if strings.Contains(e.Error(), awsPath) {
			reported = true
		}
	}
	if !reported {
		t.Errorf("Deploy must report the skipped pre-existing file as an error: %v", errs)
	}

	// The other decoys must still have been planted.
	if len(m.Decoys) != 2 {
		t.Errorf("expected the other 2 decoys to deploy, got %d", len(m.Decoys))
	}
}
