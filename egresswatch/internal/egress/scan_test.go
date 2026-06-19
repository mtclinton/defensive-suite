package egress

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/egresswatch/internal/report"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/runner"
)

func writeAllowlist(t *testing.T, json string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "egress.json")
	if err := os.WriteFile(p, []byte(json), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanFlagsConnectionNotOnAllowlist(t *testing.T) {
	allow := writeAllowlist(t, `{"rules":[{"name":"https","proto":"tcp","ports":[443]}]}`)
	ss := `Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp ESTAB 0 0 192.168.1.5:5000 140.82.112.3:443 users:(("git",pid=10,fd=3))
tcp ESTAB 0 0 192.168.1.5:5001 23.254.164.123:4444 users:(("node",pid=66,fd=4))
`
	r := &runner.Fake{Responses: map[string]runner.Result{"ss -tunp": {Stdout: ss}}}
	findings := Scan(context.Background(), r, allow, "ss", "")
	denied := 0
	for _, f := range findings {
		if f.Severity == report.SeverityMedium && f.Rule == "egresswatch-egress-allowlist" {
			denied++
			if want := "23.254.164.123"; !contains(f.Detail, want) {
				t.Errorf("denied finding should name the bad remote %q: %q", want, f.Detail)
			}
		}
	}
	if denied != 1 {
		t.Errorf("exactly one connection (the :4444 C2) should be denied: %+v", findings)
	}
}

func TestScanNoAllowlistIsObservedOnly(t *testing.T) {
	ss := "tcp ESTAB 0 0 1.2.3.4:5 6.7.8.9:443 users:((\"x\",pid=1,fd=2))\n"
	r := &runner.Fake{Responses: map[string]runner.Result{"ss -tunp": {Stdout: ss}}}
	findings := Scan(context.Background(), r, "", "ss", "")
	for _, f := range findings {
		if f.Severity >= report.SeverityMedium {
			t.Errorf("no-allowlist mode must not produce judged findings: %+v", f)
		}
	}
	rep := report.New("egresswatch", "h", time.Unix(0, 0), findings)
	if !rep.Summary.Clean {
		t.Error("observed-only mode should stay clean")
	}
}

func TestScanProcSourceCleanAllowlist(t *testing.T) {
	// All observed remotes are loopback -> allowed by default -> clean.
	procDir := t.TempDir()
	netDir := filepath.Join(procDir, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// local 127.0.0.1:.. -> rem 127.0.0.1:443 ESTAB. 127.0.0.1 = 0100007F.
	tcp := "  sl local rem st\n   0: 0100007F:1000 0100007F:01BB 01 0 0 0 0 0 0 0 5\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	allow := writeAllowlist(t, `{"rules":[]}`)
	findings := Scan(context.Background(), &runner.Fake{}, allow, "proc", procDir)
	rep := report.New("egresswatch", "h", time.Unix(0, 0), findings)
	if !rep.Summary.Clean {
		t.Errorf("loopback-only egress with allow_loopback default should be clean: %+v", findings)
	}
}

func TestScanBadAllowlistDegrades(t *testing.T) {
	bad := writeAllowlist(t, `{"rules":[{"name":"x","cidr":"oops"}]}`)
	findings := Scan(context.Background(), &runner.Fake{}, bad, "proc", t.TempDir())
	if len(findings) != 1 || findings[0].Severity != report.SeverityLow {
		t.Errorf("a bad allowlist should degrade to a single Low finding: %+v", findings)
	}
}

func TestScanSSMissingDegradesToInfo(t *testing.T) {
	allow := writeAllowlist(t, `{"rules":[]}`)
	// Fake runner returns ErrNotFound for ss -> info, not a failure.
	findings := Scan(context.Background(), &runner.Fake{}, allow, "ss", "")
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("missing ss tool should degrade to Info: %+v", findings)
	}
}

// Regression: procDir is operator-overridable for offline forensics, so a hostile
// snapshot could place a huge /proc/net/tcp. readFileLimited must cap the read.
func TestReadFileLimitedBounds(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "tcp")
	data := make([]byte, maxProcRead+(1<<20))
	for i := range data {
		data[i] = 'a'
	}
	if err := os.WriteFile(big, data, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readFileLimited(big)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxProcRead {
		t.Errorf("read must be capped at maxProcRead=%d, got %d", maxProcRead, len(got))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
