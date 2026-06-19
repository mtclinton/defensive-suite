// Package x11lock detects QLNX's fake-X11-lockfile persistence (T1036): a
// /tmp/.X<n>-lock whose recorded PID does not belong to a running X server.
package x11lock

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
)

// LockFile is a parsed X11 lock file.
type LockFile struct {
	Path     string
	Display  int
	OwnerUID int
	PID      int // PID recorded inside the file; -1 when unparsable
}

// Proc is a minimal view of a running process.
type Proc struct {
	PID  int
	UID  int
	Comm string
}

var xServerComms = map[string]bool{
	"Xorg": true, "X": true, "Xwayland": true, "Xvfb": true, "Xephyr": true,
}

// ParseLock extracts the display number from the filename (".X<n>-lock") and the
// PID stored inside the file (X writes it as right-justified ASCII).
func ParseLock(path string, ownerUID int, content string) LockFile {
	lf := LockFile{Path: path, OwnerUID: ownerUID, PID: -1, Display: -1}
	base := filepath.Base(path)
	mid := strings.TrimSuffix(strings.TrimPrefix(base, ".X"), "-lock")
	if n, err := strconv.Atoi(mid); err == nil {
		lf.Display = n
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(content)); err == nil {
		lf.PID = pid
	}
	return lf
}

// parseProcStatComm extracts the comm field from /proc/<pid>/stat content, which
// is the text inside the first '('...')' pair (and may itself contain spaces).
func parseProcStatComm(stat string) (string, bool) {
	open := strings.IndexByte(stat, '(')
	closeIdx := strings.LastIndexByte(stat, ')')
	if open < 0 || closeIdx < 0 || closeIdx <= open+1 {
		return "", false
	}
	return stat[open+1 : closeIdx], true
}

// Evaluate decides whether a lock file is suspicious given the live process list
// and the UIDs a legitimate X server may run as. It is pure for testability.
func Evaluate(lf LockFile, procs []Proc, xServerUIDs map[int]bool) (report.Finding, bool) {
	if lf.PID <= 0 {
		return report.Finding{
			Check: "x11lock", Severity: report.SeverityMedium, Path: lf.Path,
			Title: "X11 lock file has no valid PID", Technique: "T1036",
		}, true
	}
	var owner *Proc
	for i := range procs {
		if procs[i].PID == lf.PID {
			owner = &procs[i]
			break
		}
	}
	if owner == nil {
		return report.Finding{
			Check: "x11lock", Severity: report.SeverityHigh, Path: lf.Path,
			Title:     "X11 lock file references a non-running PID (stale or fake)",
			Detail:    fmt.Sprintf("pid=%d not running", lf.PID),
			Technique: "T1036",
		}, true
	}
	if !xServerComms[owner.Comm] {
		return report.Finding{
			Check: "x11lock", Severity: report.SeverityHigh, Path: lf.Path,
			Title:     "X11 lock file PID is not an X server process",
			Detail:    fmt.Sprintf("pid=%d comm=%q", owner.PID, owner.Comm),
			Technique: "T1036",
		}, true
	}
	// comm is attacker-controllable (prctl(PR_SET_NAME)/argv[0]). A real X server
	// runs as one of the allowed UIDs; an attacker's "Xorg"-named process under
	// their own UID would otherwise pass. Enforced only when the allowlist is set.
	if len(xServerUIDs) > 0 && !xServerUIDs[owner.UID] {
		return report.Finding{
			Check: "x11lock", Severity: report.SeverityHigh, Path: lf.Path,
			Title:     "X11 lock file PID runs as a UID not allowed for an X server",
			Detail:    fmt.Sprintf("pid=%d comm=%q uid=%d", owner.PID, owner.Comm, owner.UID),
			Technique: "T1036",
		}, true
	}
	return report.Finding{}, false
}

// readLimited reads at most maxBytes from path, opened without following symlinks
// (a TOCTOU guard for the world-writable /tmp). A lock file is only a few bytes;
// this prevents an attacker redirecting us at an endless file to exhaust memory.
func readLimited(path string, maxBytes int64) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxBytes))
	return string(b)
}

func fileOwnerUID(info os.FileInfo) (int, bool) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), true
	}
	return 0, false
}

// readProcs enumerates processes from a /proc-style directory. ok is false when
// the directory cannot be read (e.g. non-Linux hosts), so the caller can fall
// back instead of treating an empty list as "no X server running".
func readProcs(procDir string) (procs []Proc, ok bool) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		statBytes, err := os.ReadFile(filepath.Join(procDir, e.Name(), "stat"))
		if err != nil {
			continue
		}
		comm, ok := parseProcStatComm(string(statBytes))
		if !ok {
			continue
		}
		p := Proc{PID: pid, Comm: comm}
		if info, err := os.Stat(filepath.Join(procDir, e.Name())); err == nil {
			if uid, ok := fileOwnerUID(info); ok {
				p.UID = uid
			}
		}
		procs = append(procs, p)
	}
	return procs, true
}

// Scan inspects every lock file matching glob. When the process table cannot be
// read, it falls back to the owner-UID allowlist: a lock owned by a configured
// X-server UID is accepted, anything else is reported informationally.
func Scan(glob string, xServerUIDs []int, procDir string) []report.Finding {
	matches, err := filepath.Glob(glob)
	if err != nil || len(matches) == 0 {
		return nil
	}
	xUIDs := map[int]bool{}
	for _, u := range xServerUIDs {
		xUIDs[u] = true
	}
	procs, haveProcs := readProcs(procDir)

	var findings []report.Finding
	for _, path := range matches {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		// A genuine X lock file is a small regular file. A symlink or device here
		// is an attacker redirecting us at e.g. /dev/zero or /proc/kcore; never
		// read it (an unbounded read would OOM this root process).
		if !info.Mode().IsRegular() {
			findings = append(findings, report.Finding{
				Check: "x11lock", Severity: report.SeverityMedium, Path: path,
				Title:     "X11 lock path is not a regular file (possible redirection)",
				Detail:    "mode=" + info.Mode().String(),
				Technique: "T1036",
			})
			continue
		}
		ownerUID := -1
		if uid, ok := fileOwnerUID(info); ok {
			ownerUID = uid
		}
		lf := ParseLock(path, ownerUID, readLimited(path, 64))

		if !haveProcs {
			if ownerUID >= 0 && xUIDs[ownerUID] {
				continue
			}
			findings = append(findings, report.Finding{
				Check: "x11lock", Severity: report.SeverityInfo, Path: path,
				Title:  "cannot verify X server (no process table); review lock file",
				Detail: fmt.Sprintf("owner_uid=%d pid=%d", ownerUID, lf.PID),
			})
			continue
		}
		if f, suspicious := Evaluate(lf, procs, xUIDs); suspicious {
			findings = append(findings, f)
		}
	}
	return findings
}
