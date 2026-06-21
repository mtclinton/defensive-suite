package respond

import (
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// autoguards.go holds the READ-ONLY /proc-resolving identity helpers the auto-
// response DECISION layer (auto.go) uses to corroborate a finding's would-be
// target against live process identity. NOTHING here acts: every function only
// reads /proc (or a test-injected fake of it). The single load-bearing rule of
// Increment 1 — the decision layer is structurally incapable of executing — is
// upheld here too: these helpers return facts, never side effects.
//
// The §3.2 binding: the auto path NEVER trusts Finding.Path as a target. It
// resolves /proc/<pid>/exe (the open image of a STILL-LIVE process), checks it
// is resident UNDER a configured StagingDir, owned by the same UID as the
// connecting process, and is NOT a protected process (PID1/sshd/agentd/
// collector/login-shell/critical units + the operator never-quarantine list).

// procInfo is the read-only snapshot of a live process the auto guards resolve.
// Live is false when the pid is gone (or never resolvable) — the auto path then
// degrades to alert-only, never acting on a dead/uncertain identity.
type procInfo struct {
	Pid       int
	Exe       string // resolved /proc/<pid>/exe target (" (deleted)" stripped)
	UID       int
	StartTime uint64 // /proc/<pid>/stat field 22 (starttime, per-boot stable)
	// ExecID is the Tetragon-style stable exec_id when the resolver can supply one.
	// The real /proc resolver leaves it "" (the kernel does not expose exec_id via
	// /proc); the bridge then identity-binds on (Pid, StartTime). A future resolver
	// or a test may populate it for the stronger exec_id match.
	ExecID string
	Live   bool
}

// procResolver reads a live process's identity from /proc. It is an interface so
// unit tests inject a fake (there is no real /proc in the test environment, and
// — more importantly — the test must prove the decision layer reaches no
// actuator regardless of what /proc says). resolve returns Live=false for an
// absent/unreadable process.
type procResolver interface {
	resolve(pid int) procInfo
}

// procRoot is the /proc mount the real resolver reads from. It is a package var
// so a test can point the REAL resolver at a fabricated /proc tree (a directory
// of fake <pid>/exe symlinks + status/stat files) and exercise the actual
// os.Readlink / deleted-marker / liveness path — closing the gap where every
// resolver test injected a fake procResolver and never ran the real code.
var procRoot = "/proc"

// realProcResolver reads the real /proc read-only. It is never the resolver in
// unit tests; it ships so a future execution increment can wire it in. Even
// then it only READS — it has no Execute, no Responder, no Executor reference.
type realProcResolver struct{}

func (realProcResolver) resolve(pid int) procInfo {
	if pid <= 0 {
		return procInfo{Pid: pid}
	}
	info := procInfo{Pid: pid}
	base := procRoot + "/" + strconv.Itoa(pid)

	// Read the /proc/<pid>/exe link TARGET directly. filepath.EvalSymlinks FAILS
	// for a fileless (T1620) process — the original image is deleted or a memfd, so
	// the link target does not resolve to an existing file — and fileless is the
	// ONLY base technique that maps to a WOULD-quarantine. Resolving via
	// EvalSymlinks alone would therefore make every fileless candidate look dead
	// (Live=false) and the shadow soak would emit ZERO quarantine candidates. So
	// read the raw link (e.g. "/tmp/.x/payload (deleted)" or "memfd:foo (deleted)")
	// and strip the kernel's trailing " (deleted)" marker.
	target, err := os.Readlink(base + "/exe")
	if err != nil {
		return info // exe link unreadable → not live / not resolvable
	}
	exe := stripDeleted(target)

	// Liveness is determined by the process still EXISTING, not by the exe target
	// existing on disk: a fileless process is alive but its image is gone. Probe a
	// stable per-process file (status, then stat) to confirm /proc/<pid> is real.
	uid, uidOK := readProcUID(base + "/status")
	st, stOK := readStartTime(base + "/stat")
	if !uidOK && !stOK {
		return info // /proc/<pid> not readable → treat as not live
	}
	info.Live = true
	if uidOK {
		info.UID = uid
	}
	if stOK {
		info.StartTime = st
	}

	// Best-effort canonicalization: only when the target still exists on disk
	// (a NON-fileless candidate). For a deleted/memfd image EvalSymlinks fails;
	// keep the stripped link target so the underStagingDir residency check still
	// sees e.g. "/tmp/.x/payload".
	if canon, err := filepath.EvalSymlinks(base + "/exe"); err == nil {
		exe = canon
	}
	info.Exe = exe
	return info
}

// stripDeleted removes the kernel's trailing " (deleted)" marker the /proc exe
// link carries for a fileless/deleted image (e.g. "/tmp/.x/payload (deleted)" or
// "memfd:foo (deleted)"), returning the underlying path so residency checks and
// the would-action target see the real staging path. A path without the marker
// is returned unchanged.
func stripDeleted(target string) string {
	return strings.TrimSuffix(strings.TrimSpace(target), " (deleted)")
}

// readProcUID parses the real UID (first field of the "Uid:" line) from a
// /proc/<pid>/status file. Best-effort: ok=false on any read/parse failure.
func readProcUID(statusPath string) (int, bool) {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, false
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(ln, "Uid:") {
			fields := strings.Fields(ln)
			if len(fields) >= 2 {
				if uid, err := strconv.Atoi(fields[1]); err == nil {
					return uid, true
				}
			}
			return 0, false
		}
	}
	return 0, false
}

// readStartTime parses field 22 (starttime) from a /proc/<pid>/stat line. The
// comm field (field 2) is parenthesized and may itself contain spaces/")", so we
// split on the LAST ')' before counting space-separated fields, matching the
// kernel's documented format. Best-effort: ok=false on any failure.
func readStartTime(statPath string) (uint64, bool) {
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0, false
	}
	s := string(data)
	close := strings.LastIndexByte(s, ')')
	if close < 0 || close+1 >= len(s) {
		return 0, false
	}
	// After comm: fields 3.. are space-separated. starttime is field 22, i.e.
	// index 19 in the post-comm slice (field 3 == index 0).
	rest := strings.Fields(s[close+1:])
	const startTimeIdx = 19
	if len(rest) <= startTimeIdx {
		return 0, false
	}
	v, err := strconv.ParseUint(rest[startTimeIdx], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// underStagingDir reports whether realpath is resident under any configured
// staging dir (the §3.2 residency constraint that collapses the DoS-via-defender
// surface — a forged finding naming /opt/... will not match). Comparison is on
// whole path segments so "/tmp/x" matches "/tmp/" but "/tmpfoo" does not.
func underStagingDir(realpath string, stagingDirs []string) bool {
	clean := path.Clean(realpath)
	for _, d := range stagingDirs {
		d = path.Clean(strings.TrimSpace(d))
		if d == "" || d == "/" {
			continue // a "/" staging dir would make everything staging-resident
		}
		if clean == d || strings.HasPrefix(clean, d+"/") {
			return true
		}
	}
	return false
}

// defaultProtectedPaths is the built-in self-protection set, anchored to REAL
// on-disk ABSOLUTE paths — NOT attacker-choosable basenames. The old basename set
// ("sshd", "bash", …) let an attacker name a /tmp dropper `bash` and earn
// force-alert-only (auto-eligibility evasion), and conversely force-protected any
// legitimately staged binary that happened to share a basename. Protection is now
// the exec's resolved path being EQUAL TO (or under) one of these system
// locations; a binary merely NAMED `bash` under a staging dir is NOT protected.
// agentd itself is protected separately via os.Executable() (see selfExePath).
var defaultProtectedPaths = []string{
	"/usr/sbin/sshd",
	"/usr/bin/sshd",
	"/sbin/sshd",
	"/usr/local/sbin/sshd",
	"/usr/local/bin/collector",
	"/usr/bin/collector",
	"/usr/local/bin/agentd",
	"/usr/bin/agentd",
	"/sbin/init",
	"/usr/lib/systemd/systemd",
	"/lib/systemd/systemd",
	// Login shells at their canonical system locations only. A staging-resident
	// exe NAMED bash/zsh/sh is deliberately NOT covered — basename matching was
	// the evasion bug; the StagingDir + identity bind is the primary control.
	"/bin/bash", "/usr/bin/bash",
	"/bin/zsh", "/usr/bin/zsh",
	"/bin/sh", "/usr/bin/sh",
	"/bin/login", "/usr/bin/login",
}

// selfExePath returns the agentd binary's own resolved absolute path (via
// os.Executable), or "" if it cannot be determined. It is computed once at Bridge
// construction so the auto path never quarantines agentd itself even if a future
// increment runs agentd from a non-default location. Pulled out as a var so tests
// can inject a deterministic value.
var selfExePath = func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if canon, err := filepath.EvalSymlinks(exe); err == nil {
		return canon
	}
	return exe
}

// isProtectedExe reports whether the resolved exe path is a protected process the
// auto path must never quarantine. Protection is anchored to REAL identity, never
// to an attacker-choosable basename:
//   - PID<=1 (init/PID 1),
//   - the exe path equals (or is under) the agentd self-exe path (os.Executable),
//   - the exe path equals (or is under) any configured protected ABSOLUTE path
//     (sshd/collector/login shells/systemd at their canonical locations),
//   - the exe path equals (or is under) any operator never-quarantine entry.
//
// A staging-resident dropper named "bash" therefore is NOT protected (its path is
// /tmp/…/bash, not /bin/bash). It is pure (no I/O) so it is exhaustively
// unit-testable: selfExe and protectedPaths are passed in.
func isProtectedExe(info procInfo, selfExe string, protectedPaths, neverQuarantine []string) bool {
	if info.Pid <= 1 {
		return true
	}
	clean := path.Clean(info.Exe)
	if clean == "" || clean == "." {
		return false
	}
	matches := func(candidate string) bool {
		candidate = path.Clean(strings.TrimSpace(candidate))
		if candidate == "" || candidate == "/" || candidate == "." {
			return false
		}
		return clean == candidate || strings.HasPrefix(clean, candidate+"/")
	}
	if selfExe != "" && matches(selfExe) {
		return true
	}
	for _, p := range protectedPaths {
		if matches(p) {
			return true
		}
	}
	for _, n := range neverQuarantine {
		if matches(n) {
			return true
		}
	}
	return false
}
