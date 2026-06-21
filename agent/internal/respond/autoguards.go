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
	Exe       string // realpath of /proc/<pid>/exe
	UID       int
	StartTime uint64 // /proc/<pid>/stat field 22
	Live      bool
}

// procResolver reads a live process's identity from /proc. It is an interface so
// unit tests inject a fake (there is no real /proc in the test environment, and
// — more importantly — the test must prove the decision layer reaches no
// actuator regardless of what /proc says). resolve returns Live=false for an
// absent/unreadable process.
type procResolver interface {
	resolve(pid int) procInfo
}

// realProcResolver reads the real /proc read-only. It is never the resolver in
// unit tests; it ships so a future execution increment can wire it in. Even
// then it only READS — it has no Execute, no Responder, no Executor reference.
type realProcResolver struct{}

func (realProcResolver) resolve(pid int) procInfo {
	if pid <= 0 {
		return procInfo{Pid: pid}
	}
	info := procInfo{Pid: pid}
	base := "/proc/" + strconv.Itoa(pid)
	exe, err := filepath.EvalSymlinks(base + "/exe")
	if err != nil {
		return info // process gone / unreadable → not live
	}
	info.Exe = exe
	info.Live = true
	if uid, ok := readProcUID(base + "/status"); ok {
		info.UID = uid
	}
	if st, ok := readStartTime(base + "/stat"); ok {
		info.StartTime = st
	}
	return info
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

// protectedBinaries is the built-in self-protection set: realpath basenames the
// auto path must never select as a quarantine target, regardless of residency.
// This is a BACKSTOP — the primary control is the StagingDir + same-UID + live-
// identity bind. A staging-resident sshd/agentd is still refused here.
var protectedBinaries = map[string]bool{
	"sshd":      true,
	"agentd":    true,
	"collector": true,
	"systemd":   true,
	"init":      true,
	"bash":      true, // login shell heuristic
	"zsh":       true,
	"sh":        true,
	"login":     true,
}

// isProtectedExe reports whether the resolved exe realpath is a protected
// process the auto path must never quarantine: PID<=1, a built-in protected
// basename (sshd/agentd/collector/login shell/critical units), or any entry in
// the operator-configured never-quarantine list (matched as an exact path or a
// path-prefix). It is pure (no I/O) so it is exhaustively unit-testable.
func isProtectedExe(info procInfo, neverQuarantine []string) bool {
	if info.Pid <= 1 {
		return true
	}
	if protectedBinaries[filepath.Base(info.Exe)] {
		return true
	}
	clean := path.Clean(info.Exe)
	for _, n := range neverQuarantine {
		n = path.Clean(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if clean == n || strings.HasPrefix(clean, n+"/") {
			return true
		}
	}
	return false
}
