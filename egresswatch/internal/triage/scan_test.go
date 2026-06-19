package triage

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/egresswatch/internal/report"
)

// mkProc writes a synthetic /proc/<pid> with the given markers. fdSockets maps
// an fd number to a socket inode; the fd entry is a symlink whose literal target
// is "socket:[inode]" (it need not resolve — os.Readlink returns the text).
func mkProc(t *testing.T, procDir string, pid int, comm, exeTarget, wchan string, fdSockets map[string]uint64) {
	t.Helper()
	base := filepath.Join(procDir, itoa(pid))
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", itoa(pid)+" ("+comm+") S 1 "+itoa(pid)+" "+itoa(pid)+" 0 -1 0")
	write("status", "Name:\t"+comm+"\nUid:\t0\t0\t0\t0\n")
	if wchan != "" {
		write("wchan", wchan)
	}
	if exeTarget != "" {
		if err := os.Symlink(exeTarget, filepath.Join(base, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	for fd, ino := range fdSockets {
		target := "socket:[" + utoa(ino) + "]"
		if err := os.Symlink(target, filepath.Join(base, "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
}

func itoa(n int) string    { return strconv.Itoa(n) }
func utoa(n uint64) string { return strconv.FormatUint(n, 10) }

func writePacket(t *testing.T, procDir, content string) {
	t.Helper()
	netDir := filepath.Join(procDir, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "packet"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sevCount(findings []report.Finding, sev report.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

// The verification target: a clean machine with NO raw packet sockets and no
// markers produces zero judged findings. The packet file is present but lists
// only a benign SOCK_DGRAM (dhclient-style) socket, even with Running=1.
func TestScanCleanHostNoBPFDoor(t *testing.T) {
	procDir := t.TempDir()
	writePacket(t, procDir, "sk RefCnt Type Proto Iface R Rmem User Inode\nffff00 3 2 0000 0 1 0 1000 5\n")
	mkProc(t, procDir, 1, "systemd", "/usr/lib/systemd/systemd", "ep_poll", nil)
	mkProc(t, procDir, 1200, "sshd", "/usr/sbin/sshd", "poll_schedule_timeout", map[string]uint64{"3": 5})

	findings := Scan(procDir, []string{}) // no mutex candidates
	if sevCount(findings, report.SeverityCritical) != 0 {
		t.Errorf("clean host must have zero critical findings: %+v", findings)
	}
	if sevCount(findings, report.SeverityHigh) != 0 {
		t.Errorf("clean host (SOCK_DGRAM only) must have no raw-socket high finding: %+v", findings)
	}
	if sevCount(findings, report.SeverityMedium) != 0 {
		t.Errorf("clean host must have no medium findings: %+v", findings)
	}
	rep := report.New("egresswatch", "h", time.Unix(0, 0), findings)
	if !rep.Summary.Clean {
		t.Errorf("clean host must stay clean (Running=1 on a SOCK_DGRAM is benign): %+v", findings)
	}
}

// Regression for the R-column false positive at the Scan level: a benign process
// (real exe, not blocked) holding a *raw* AF_PACKET socket — e.g. tcpdump — must
// NOT be Critical. It surfaces as High "review", never as a confirmed implant.
func TestScanBenignRawSocketIsNotCritical(t *testing.T) {
	procDir := t.TempDir()
	writePacket(t, procDir, "sk RefCnt Type Proto Iface R Rmem User Inode\nffff00 3 3 0003 2 1 0 0 34567\n")
	mkProc(t, procDir, 1, "systemd", "/usr/lib/systemd/systemd", "ep_poll", nil)
	mkProc(t, procDir, 2222, "tcpdump", "/usr/bin/tcpdump", "poll_schedule_timeout",
		map[string]uint64{"3": 34567})

	findings := Scan(procDir, []string{})
	if sevCount(findings, report.SeverityCritical) != 0 {
		t.Errorf("a benign tcpdump-style raw socket must not be Critical: %+v", findings)
	}
	var sawReview bool
	for _, f := range findings {
		if f.Path == "/proc/2222" && f.Severity == report.SeverityHigh && f.Technique == "T1205.002" {
			sawReview = true
		}
	}
	if !sawReview {
		t.Errorf("the raw socket should still surface as a High review finding: %+v", findings)
	}
}

// A BPFDoor-class implant: a raw AF_PACKET socket attributed to a process that
// also runs from a deleted exe and is blocked in packet_recvmsg. The corroborated
// raw socket is Critical.
func TestScanDetectsBPFDoor(t *testing.T) {
	procDir := t.TempDir()
	writePacket(t, procDir, "sk RefCnt Type Proto Iface R Rmem User Inode\nffff00 3 3 0003 2 1 0 0 34567\n")
	mkProc(t, procDir, 1, "systemd", "/usr/lib/systemd/systemd", "ep_poll", nil)
	// The implant: holds the raw socket inode 34567, deleted exe, blocked.
	mkProc(t, procDir, 31337, "/usr/sbin/console-kit-daemon", "/dev/shm/kdmtmp (deleted)", "packet_recvmsg",
		map[string]uint64{"3": 34567})

	findings := Scan(procDir, []string{})

	var sawRawCritical, sawDeleted, sawBlocked bool
	for _, f := range findings {
		switch {
		case f.Technique == "T1205.002" && f.Severity == report.SeverityCritical && f.Path == "/proc/31337":
			sawRawCritical = true
		case f.Technique == "T1620" && f.Severity == report.SeverityCritical:
			sawDeleted = true
		case f.Technique == "T1205.002" && f.Severity == report.SeverityHigh && f.Path == "/proc/31337":
			sawBlocked = true
		}
	}
	if !sawRawCritical {
		t.Errorf("a raw socket corroborated by deleted exe + block must be critical: %+v", findings)
	}
	if !sawDeleted {
		t.Errorf("must flag the deleted/fileless exe as critical (raw socket held): %+v", findings)
	}
	if !sawBlocked {
		t.Errorf("must flag the packet_recvmsg block as high (raw socket held): %+v", findings)
	}
	// Exit must be non-clean.
	rep := report.New("egresswatch", "h", time.Unix(0, 0), findings)
	if rep.ExitCode() != 2 {
		t.Errorf("a detected implant must yield exit 2, got %d", rep.ExitCode())
	}
}

func TestScanFlagsZeroByteMutex(t *testing.T) {
	procDir := t.TempDir()
	writePacket(t, procDir, "sk RefCnt Type Proto Iface R Rmem User Inode\n")
	mutex := filepath.Join(t.TempDir(), "haldrund.pid")
	if err := os.WriteFile(mutex, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	nonEmpty := filepath.Join(filepath.Dir(mutex), "other.pid")
	if err := os.WriteFile(nonEmpty, []byte("123"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := Scan(procDir, []string{mutex, nonEmpty, "/no/such/path"})
	hits := 0
	for _, f := range findings {
		if f.Path == mutex && f.Severity == report.SeverityMedium {
			hits++
		}
		if f.Path == nonEmpty {
			t.Errorf("non-empty lock file must not be flagged: %+v", f)
		}
	}
	if hits != 1 {
		t.Errorf("want exactly one zero-byte mutex finding: %+v", findings)
	}
}

// Regression: a hostile offline snapshot can put a huge file at procDir/net/packet.
// readFileLimited must cap the read at maxProcRead so the tool cannot be OOM'd.
func TestReadFileLimitedBounds(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "packet")
	// Write maxProcRead + 1 MiB of data.
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

func TestScanMissingPacketFileDegrades(t *testing.T) {
	procDir := t.TempDir() // no net/packet, no pids
	findings := Scan(procDir, []string{})
	// Should be info-only, never crash, and stay clean.
	rep := report.New("egresswatch", "h", time.Unix(0, 0), findings)
	if !rep.Summary.Clean {
		t.Errorf("a host without /proc/net/packet should degrade to info, stay clean: %+v", findings)
	}
}
