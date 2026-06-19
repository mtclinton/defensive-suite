package triage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/mtclinton/defensive-suite/egresswatch/internal/report"
)

// maxProcRead bounds every /proc read. ProcDir is operator-overridable for
// offline-snapshot forensics, so a hostile snapshot could substitute a huge
// "/proc/net/packet" or per-pid file and OOM the tool. Genuine /proc files are
// far under this; 8 MiB is generous headroom while staying bounded.
const maxProcRead = 8 << 20 // 8 MiB

// readFileLimited reads at most maxProcRead bytes from path. It returns the same
// error shape as os.ReadFile for the open failure, so callers can branch on err.
func readFileLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxProcRead))
}

// DefaultMutexCandidates are the well-known zero-byte single-instance guard
// paths associated with BPFDoor / Symbiote and their lineage. The triage flags
// any of these that exists as a zero-byte regular file. The list is a starting
// signal, not an allowlist; a zero-byte file here is suspicious but corroborated
// by the socket/exe/stack markers before it is treated as confirmation.
var DefaultMutexCandidates = []string{
	"/var/run/haldrund.pid",
	"/var/run/kdevrund.pid",
	"/var/run/xinetd.lock",
	"/var/run/initd.lock",
	"/dev/shm/kdmtmpflush",
	"/dev/shm/.. ", // trailing-space hidden name seen in the wild
	"/tmp/.bpfdoor.lock",
}

// Process is the per-PID view the triage assembles from /proc.
type Process struct {
	PID          int
	Comm         string
	UID          int
	ExeTarget    string   // /proc/<pid>/exe readlink (may be "(deleted)")
	SocketInodes []uint64 // inodes from /proc/<pid>/fd
	Wchan        string   // /proc/<pid>/wchan
	Stack        string   // /proc/<pid>/stack (often unreadable without privilege)
	RawInodes    []uint64 // intersection with AF_PACKET SOCK_RAW socket inodes
}

// Scan reads procDir + the mutex candidate paths and returns triage findings.
// When mutexCandidates is nil, DefaultMutexCandidates is used. Raw packet
// sockets are surfaced and attributed to PIDs, but only escalate to Critical
// when corroborated by another marker (deleted exe / packet_recvmsg block /
// zero-byte mutex). /proc cannot confirm an attached BPF filter — that remains
// the eBPF sensor's job.
func Scan(procDir string, mutexCandidates []string) []report.Finding {
	if mutexCandidates == nil {
		mutexCandidates = DefaultMutexCandidates
	}
	var findings []report.Finding

	// --- raw AF_PACKET sockets ---
	rawSocks := map[uint64]bool{}
	packetText, err := readFileLimited(filepath.Join(procDir, "net", "packet"))
	if err != nil {
		findings = append(findings, report.Finding{
			Check: "triage", Severity: report.SeverityInfo,
			Title:  "could not read /proc/net/packet; AF_PACKET socket triage skipped",
			Detail: err.Error(),
		})
	} else {
		socks := ParsePacketSockets(string(packetText))
		for _, ino := range RawSocketInodes(socks) {
			rawSocks[ino] = true
		}
		// A raw AF_PACKET socket, even before attribution to a PID, is worth
		// surfacing (attribution may fail if the implant hides /proc), but a bare
		// raw socket is common and benign, so this is Low, not a judged finding.
		if len(rawSocks) > 0 {
			findings = append(findings, report.Finding{
				Check: "triage", Severity: report.SeverityLow,
				Title:  "raw AF_PACKET socket(s) present (review)",
				Detail: fmt.Sprintf("%d raw packet socket(s); attributing to processes", len(rawSocks)),
				Rule:   "egresswatch-magic-packet",
			})
		}
	}

	// --- per-process enumeration ---
	procs, ok := readProcesses(procDir)
	if !ok {
		findings = append(findings, report.Finding{
			Check: "triage", Severity: report.SeverityInfo,
			Title: "could not enumerate processes (non-Linux host or no /proc); per-process triage skipped",
		})
	}
	for i := range procs {
		p := &procs[i]
		for _, ino := range p.SocketInodes {
			if rawSocks[ino] {
				p.RawInodes = append(p.RawInodes, ino)
			}
		}
		findings = append(findings, evaluateProcess(*p)...)
	}

	// --- zero-byte mutex/lock files ---
	findings = append(findings, scanMutexes(mutexCandidates)...)

	return findings
}

// evaluateProcess turns one Process's markers into findings. It is the pure
// scoring step (no I/O) so the marker-to-severity mapping is unit-testable.
func evaluateProcess(p Process) []report.Finding {
	var findings []report.Finding
	pidPath := "/proc/" + strconv.Itoa(p.PID)

	hasRaw := len(p.RawInodes) > 0
	blocked := WchanIsPacketRecv(p.Wchan) || StackBlockedInPacketRecv(p.Stack)
	deleted := ExeIsDeleted(p.ExeTarget)
	// A bare raw socket is common and benign (tcpdump, dhclient, lldpd). It only
	// becomes a BPFDoor-class signal when corroborated by another marker on the
	// same process. /proc cannot tell us whether a BPF filter is attached, so the
	// raw socket is the surface, not the confirmation — the eBPF sensor confirms.
	rawCorroborated := hasRaw && (deleted || blocked)

	// (1) Raw AF_PACKET socket held by this process. Critical only when
	// corroborated; an uncorroborated bare raw socket is High "review", not a
	// confirmed implant.
	if hasRaw {
		sev := report.SeverityHigh
		title := "process holds a raw AF_PACKET socket (review)"
		if rawCorroborated {
			sev = report.SeverityCritical
			title = "process holds a raw AF_PACKET socket with corroborating BPFDoor-class markers"
		}
		findings = append(findings, report.Finding{
			Check: "triage", Severity: sev, Path: pidPath,
			Title: title,
			Detail: fmt.Sprintf("pid=%d comm=%q uid=%d exe=%q raw_inodes=%v deleted_exe=%t packet_recv_block=%t",
				p.PID, p.Comm, p.UID, p.ExeTarget, p.RawInodes, deleted, blocked),
			Technique: "T1205.002", Rule: "egresswatch-magic-packet",
		})
	}

	// (2) Fileless / deleted executable — strongest when it also holds a raw socket.
	if deleted {
		sev := report.SeverityHigh
		if hasRaw {
			sev = report.SeverityCritical
		}
		findings = append(findings, report.Finding{
			Check: "triage", Severity: sev, Path: pidPath,
			Title:     "process running from a deleted/fileless executable",
			Detail:    fmt.Sprintf("pid=%d comm=%q exe=%q", p.PID, p.Comm, p.ExeTarget),
			Technique: "T1620",
		})
	}

	// (4) Thread blocked in packet_recvmsg waiting on the magic packet.
	if blocked {
		sev := report.SeverityMedium
		if hasRaw {
			sev = report.SeverityHigh
		}
		findings = append(findings, report.Finding{
			Check: "triage", Severity: sev, Path: pidPath,
			Title:     "thread blocked in packet_recvmsg (awaiting magic packet)",
			Detail:    fmt.Sprintf("pid=%d comm=%q wchan=%q", p.PID, p.Comm, p.Wchan),
			Technique: "T1205.002",
		})
	}
	return findings
}

func scanMutexes(candidates []string) []report.Finding {
	var findings []report.Finding
	for _, path := range candidates {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if IsZeroByteMutex(info.Mode().IsRegular(), info.Size()) {
			findings = append(findings, report.Finding{
				Check: "triage", Severity: report.SeverityMedium, Path: path,
				Title:     "zero-byte mutex/lock file matching a known BPFDoor-class guard",
				Detail:    "single-instance lock dropped by passive backdoors; corroborate with socket/exe markers",
				Technique: "T1205.002",
			})
		}
	}
	return findings
}

// readProcesses enumerates processes from a /proc-style directory and reads the
// per-PID markers. ok is false when the directory cannot be read so the caller
// can distinguish "no processes" from "no /proc".
func readProcesses(procDir string) (procs []Process, ok bool) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		base := filepath.Join(procDir, e.Name())
		p := Process{PID: pid, UID: -1}

		if b, err := readFileLimited(filepath.Join(base, "stat")); err == nil {
			if comm, ok := ParseStatComm(string(b)); ok {
				p.Comm = comm
			}
		}
		if b, err := readFileLimited(filepath.Join(base, "status")); err == nil {
			if uid, ok := ParseStatusUID(string(b)); ok {
				p.UID = uid
			}
		}
		if t, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
			p.ExeTarget = t
		}
		if b, err := readFileLimited(filepath.Join(base, "wchan")); err == nil {
			p.Wchan = string(b)
		}
		if b, err := readFileLimited(filepath.Join(base, "stack")); err == nil {
			p.Stack = string(b)
		}
		p.SocketInodes = readFDInodes(filepath.Join(base, "fd"))

		procs = append(procs, p)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, true
}

// readFDInodes reads /proc/<pid>/fd, resolves each entry's symlink, and returns
// the socket inodes. Unreadable entries (a process exiting, or one the implant
// has hidden) are skipped.
func readFDInodes(fdDir string) []uint64 {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	links := map[string]string{}
	for _, e := range entries {
		if t, err := os.Readlink(filepath.Join(fdDir, e.Name())); err == nil {
			links[e.Name()] = t
		}
	}
	return ParseFDSocketInodes(links)
}
