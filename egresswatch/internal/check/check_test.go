package check

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/egresswatch/internal/config"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/report"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/runner"
)

func fixedClock() time.Time { return time.Unix(1700000000, 0).UTC() }

// A fully clean host: a /proc with no raw packet sockets and only loopback
// egress, judged against an empty allowlist (loopback allowed) -> exit 0.
func TestRunCleanHostExit0(t *testing.T) {
	procDir := t.TempDir()
	netDir := filepath.Join(procDir, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Empty packet table (header only) and a loopback-only tcp table.
	mustWrite(t, filepath.Join(netDir, "packet"), "sk RefCnt Type Proto Iface R Rmem User Inode\n")
	mustWrite(t, filepath.Join(netDir, "tcp"), "  sl local rem st\n   0: 0100007F:1000 0100007F:01BB 01 0 0 0 0 0 0 0 5\n")

	allow := filepath.Join(t.TempDir(), "egress.json")
	mustWrite(t, allow, `{"rules":[]}`)

	cfg := config.Config{ProcDir: procDir, AllowlistPath: allow, ConnSource: "proc"}
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{Clock: fixedClock})

	if rep.Tool != "egresswatch" {
		t.Errorf("tool=%q", rep.Tool)
	}
	if !rep.Time.Equal(fixedClock()) {
		t.Errorf("clock not injected: %v", rep.Time)
	}
	if rep.ExitCode() != 0 || !rep.Summary.Clean {
		t.Errorf("clean host should exit 0: %+v", rep.Summary)
	}
}

// A compromised host: a raw AF_PACKET socket attributed to a process that is ALSO
// blocked in packet_recvmsg (the corroborating marker that escalates the raw
// socket to Critical — a bare raw socket alone is only High "review"), plus a
// connection to an unallowlisted C2 -> exit 2.
func TestRunCompromisedHostExit2(t *testing.T) {
	procDir := t.TempDir()
	netDir := filepath.Join(procDir, "net")
	if err := os.MkdirAll(filepath.Join(procDir, "1337", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(netDir, "packet"), "sk RefCnt Type Proto Iface R Rmem User Inode\nffff 3 3 0003 2 1 0 0 77777\n")
	mustWrite(t, filepath.Join(procDir, "1337", "stat"), "1337 (kdevtmpfs) S 1 1337 1337 0 -1 0")
	mustWrite(t, filepath.Join(procDir, "1337", "status"), "Name:\tkdevtmpfs\nUid:\t0\t0\t0\t0\n")
	// Corroborating marker: the implant thread is parked in packet_recvmsg.
	mustWrite(t, filepath.Join(procDir, "1337", "wchan"), "packet_recvmsg")
	if err := os.Symlink("socket:[77777]", filepath.Join(procDir, "1337", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	// Egress to a C2 not on the allowlist (only https/443 allowed).
	mustWrite(t, filepath.Join(netDir, "tcp"), "  sl local rem st\n   0: 0500A8C0:D431 7BA4FE17:115C 01 0 0 0 0 0 0 0 5\n")

	allow := filepath.Join(t.TempDir(), "egress.json")
	mustWrite(t, allow, `{"rules":[{"name":"https","proto":"tcp","ports":[443]}]}`)

	cfg := config.Config{ProcDir: procDir, AllowlistPath: allow, ConnSource: "proc"}
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{Clock: fixedClock})

	if rep.ExitCode() != 2 {
		t.Fatalf("compromised host must exit 2: %+v", rep.Summary)
	}
	var sawTriageCrit, sawEgressDeny bool
	for _, f := range rep.Findings {
		if f.Check == "triage" && f.Severity == report.SeverityCritical {
			sawTriageCrit = true
		}
		if f.Check == "egress" && f.Severity == report.SeverityMedium {
			sawEgressDeny = true
		}
	}
	if !sawTriageCrit {
		t.Error("expected a critical triage finding for the filtered packet socket")
	}
	if !sawEgressDeny {
		t.Error("expected a medium egress finding for the unallowlisted C2")
	}
}

// Regression for the /proc/net/packet "R column == filter" false positive: a
// benign sniffer (tcpdump) holding a raw AF_PACKET socket, with a real exe and no
// other marker, must NOT produce a Critical finding and must not flip exit to 2
// on its own. (Egress is loopback-only so it cannot mask the result.)
func TestRunBenignRawSocketNotCritical(t *testing.T) {
	procDir := t.TempDir()
	netDir := filepath.Join(procDir, "net")
	if err := os.MkdirAll(filepath.Join(procDir, "1500", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Raw SOCK_RAW(3) socket with Running=1 — exactly what tcpdump shows.
	mustWrite(t, filepath.Join(netDir, "packet"), "sk RefCnt Type Proto Iface R Rmem User Inode\nffff 3 3 0003 2 1 0 0 88888\n")
	mustWrite(t, filepath.Join(procDir, "1500", "stat"), "1500 (tcpdump) S 1 1500 1500 0 -1 0")
	mustWrite(t, filepath.Join(procDir, "1500", "status"), "Name:\ttcpdump\nUid:\t0\t0\t0\t0\n")
	mustWrite(t, filepath.Join(procDir, "1500", "wchan"), "ep_poll")
	if err := os.Symlink("/usr/bin/tcpdump", filepath.Join(procDir, "1500", "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[88888]", filepath.Join(procDir, "1500", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(netDir, "tcp"), "  sl local rem st\n   0: 0100007F:1000 0100007F:01BB 01 0 0 0 0 0 0 0 5\n")
	allow := filepath.Join(t.TempDir(), "egress.json")
	mustWrite(t, allow, `{"rules":[]}`)

	cfg := config.Config{ProcDir: procDir, AllowlistPath: allow, ConnSource: "proc"}
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{Clock: fixedClock})

	for _, f := range rep.Findings {
		if f.Check == "triage" && f.Severity == report.SeverityCritical {
			t.Errorf("benign raw socket must not yield a Critical triage finding: %+v", f)
		}
	}
}

func TestRunSkipFlags(t *testing.T) {
	procDir := t.TempDir() // empty -> triage emits info findings, egress would too
	cfg := config.Config{ProcDir: procDir, ConnSource: "proc"}

	onlyEgress := Run(context.Background(), cfg, &runner.Fake{}, Options{SkipTriage: true, Clock: fixedClock})
	for _, f := range onlyEgress.Findings {
		if f.Check == "triage" {
			t.Errorf("SkipTriage should suppress triage findings: %+v", f)
		}
	}
	onlyTriage := Run(context.Background(), cfg, &runner.Fake{}, Options{SkipEgress: true, Clock: fixedClock})
	for _, f := range onlyTriage.Findings {
		if f.Check == "egress" {
			t.Errorf("SkipEgress should suppress egress findings: %+v", f)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
