package respond

import (
	"fmt"
	"path"
	"strconv"
	"strings"
)

// Guards is the pure, configurable policy that Validate enforces. It is the
// "allow/deny target list" from the threat model: the interfaces that must stay
// up, where quarantined files may land, and the critical paths a quarantine must
// never touch. SelfPID is the agent's own PID (refuse to kill ourselves).
type Guards struct {
	// MgmtIfaces are management/keep-up interfaces (SSH/Tailscale). Isolating one
	// would lock the operator out, so isolate refuses them.
	MgmtIfaces []string
	// QuarantineDir is where quarantine moves files. Informational for guards; the
	// executor uses it.
	QuarantineDir string
	// CriticalPaths is the denylist of path prefixes a quarantine must never
	// touch (system dirs). "/" alone matches the root itself.
	CriticalPaths []string
	// StagingDirs is the POSITIVE allowlist of dirs an unquarantine ORIGIN must
	// be resident under (§4.2/G5). The only legitimate auto-undo origin is a file
	// that was quarantined FROM a StagingDir, and the manual reverse of such a
	// quarantine is likewise staging-resident. This is the clean fix for the
	// unquarantine-clobber surface: the quarantine-SOURCE CriticalPaths denylist is
	// NOT a valid restore-DESTINATION filter (it permits /root/.bashrc,
	// ~/.ssh/authorized_keys, /var/spool/cron/...), so unquarantine constrains the
	// origin with this allowlist instead, never the denylist.
	StagingDirs []string
	// SelfPID is agentd's own PID; kill refuses it (and PID<=1).
	SelfPID int
}

// DefaultGuards returns a conservative baseline: the kernel pseudo-filesystems
// and the standard system directories are off-limits to quarantine, "lo" is
// always a keep-up interface, and "/" can never be quarantined.
func DefaultGuards() Guards {
	return Guards{
		MgmtIfaces:    []string{"lo"},
		QuarantineDir: "/var/lib/agentd/quarantine",
		CriticalPaths: []string{
			"/proc", "/sys", "/dev",
			"/bin", "/sbin", "/usr", "/lib", "/boot", "/etc",
			// /lib* — /lib64, /libexec, etc. are covered by the prefix match below.
		},
		// The default staging set mirrors config.StagingDirs: the only dirs an
		// unquarantine origin may legitimately land in. NOTE: /var/tmp is a staging
		// dir, so the unquarantine origin filter must NOT use a blanket /var
		// denylist — the StagingDirs allowlist is the correct control.
		StagingDirs: []string{"/tmp", "/dev/shm", "/var/tmp"},
	}
}

// Validate is PURE: it inspects req against guards and returns nil if the action
// is permitted, or a descriptive error if a guardrail refuses it. It performs no
// I/O and has no side effects, so it is exhaustively unit-testable. Validate
// runs before any audit-intent or execution.
func (g Guards) Validate(req Request) error {
	switch req.Action {
	case ActionKill:
		return g.validateKill(req)
	case ActionIsolate:
		return g.validateIsolate(req)
	case ActionQuarantine:
		return g.validateQuarantine(req)
	case ActionQuarantineFD:
		return g.validateQuarantineFD(req)
	case ActionRevokeKey:
		return g.validateRevokeKey(req)
	case ActionBlockHash:
		return g.validateBlockHash(req)
	case ActionUnquarantine:
		return g.validateUnquarantine(req)
	case ActionDeIsolate:
		return g.validateDeIsolate(req)
	case ActionRestoreKey:
		return g.validateRestoreKey(req)
	default:
		return fmt.Errorf("unknown action %q", req.Action)
	}
}

// validateKill: Target must be a numeric PID; refuse PID<=1 (init/kthreads), the
// agent's own PID, and any non-numeric target.
func (g Guards) validateKill(req Request) error {
	pid, err := strconv.Atoi(strings.TrimSpace(req.Target))
	if err != nil {
		return fmt.Errorf("kill: target %q is not a numeric pid", req.Target)
	}
	if pid <= 1 {
		return fmt.Errorf("kill: refusing pid %d (<=1: init/kernel)", pid)
	}
	if g.SelfPID != 0 && pid == g.SelfPID {
		return fmt.Errorf("kill: refusing to kill agentd itself (pid %d)", pid)
	}
	return nil
}

// validateIsolate: refuse if Target names a management/keep-up interface — that
// would self-lock-out the operator.
func (g Guards) validateIsolate(req Request) error {
	iface := strings.TrimSpace(req.Target)
	if iface == "" {
		return fmt.Errorf("isolate: target interface is empty")
	}
	for _, m := range g.MgmtIfaces {
		if strings.EqualFold(iface, strings.TrimSpace(m)) {
			return fmt.Errorf("isolate: refusing to isolate management interface %q (would self-lock-out)", iface)
		}
	}
	return nil
}

// validateQuarantine: refuse paths under /proc,/sys,/dev or the critical
// denylist (/bin,/sbin,/usr,/lib*,/boot,/etc, and "/").
func (g Guards) validateQuarantine(req Request) error {
	target := strings.TrimSpace(req.Target)
	if target == "" {
		return fmt.Errorf("quarantine: target path is empty")
	}
	if !path.IsAbs(target) {
		return fmt.Errorf("quarantine: target %q must be an absolute path", target)
	}
	clean := path.Clean(target)
	if clean == "/" {
		return fmt.Errorf("quarantine: refusing the root directory %q", target)
	}
	// /lib* — the design denylists every lib variant (/lib, /lib64, /libexec, …).
	// Match the first path segment as a glob against "/lib*".
	if seg := firstSegment(clean); strings.HasPrefix(seg, "lib") {
		return fmt.Errorf("quarantine: refusing %q under critical path /lib*", target)
	}
	for _, c := range g.CriticalPaths {
		if pathUnder(clean, c) {
			return fmt.Errorf("quarantine: refusing %q under critical path %q", target, c)
		}
	}
	return nil
}

// validateRevokeKey: Target must be an authorized_keys path; require a
// "fingerprint" arg (the specific key line to remove).
func (g Guards) validateRevokeKey(req Request) error {
	target := strings.TrimSpace(req.Target)
	if target == "" {
		return fmt.Errorf("revoke-key: target path is empty")
	}
	base := path.Base(target)
	if base != "authorized_keys" && base != "authorized_keys2" {
		return fmt.Errorf("revoke-key: target %q is not an authorized_keys file", target)
	}
	if strings.TrimSpace(req.arg("fingerprint")) == "" {
		return fmt.Errorf("revoke-key: missing required \"fingerprint\" arg")
	}
	return nil
}

// validateBlockHash: Target must be a 64-hex sha256.
func (g Guards) validateBlockHash(req Request) error {
	target := strings.TrimSpace(req.Target)
	if !isSHA256(target) {
		return fmt.Errorf("block-hash: target %q is not a 64-hex sha256", req.Target)
	}
	return nil
}

// validateQuarantineFD: the identity-bound, fd-based quarantine (§3.2/§4.2). The
// Request carries the captured live identity (pid + starttime + uid + exec_id)
// and the StagingDir residency constraint; the EXECUTOR re-resolves /proc and
// acts by fd. Validate is the pure pre-check: a numeric live pid, a non-empty
// staging-dir constraint, and (defence-in-depth) the captured exe path — when
// present — must NOT be under a CriticalPaths denylist entry. The real residency
// + identity bind happens at execute time against live /proc (a lexical path here
// is never trusted as the target).
func (g Guards) validateQuarantineFD(req Request) error {
	pidStr := strings.TrimSpace(req.Target)
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("quarantine-fd: target %q is not a numeric pid", req.Target)
	}
	if pid <= 1 {
		return fmt.Errorf("quarantine-fd: refusing pid %d (<=1: init/kernel)", pid)
	}
	if strings.TrimSpace(req.arg("starttime")) == "" {
		return fmt.Errorf("quarantine-fd: missing required \"starttime\" identity arg")
	}
	staging := splitArgList(req.arg("staging_dirs"))
	if len(staging) == 0 {
		return fmt.Errorf("quarantine-fd: missing required \"staging_dirs\" residency constraint")
	}
	// Defence-in-depth: if a captured exe path is supplied, refuse it lexically if
	// it falls under a critical denylist entry (the executor re-resolves /proc and
	// re-checks staging residency by fd; this is only a backstop).
	if exe := strings.TrimSpace(req.arg("exe")); exe != "" && path.IsAbs(exe) {
		clean := path.Clean(exe)
		if seg := firstSegment(clean); strings.HasPrefix(seg, "lib") {
			return fmt.Errorf("quarantine-fd: refusing captured exe %q under critical path /lib*", exe)
		}
		for _, c := range g.CriticalPaths {
			if pathUnder(clean, c) {
				return fmt.Errorf("quarantine-fd: refusing captured exe %q under critical path %q", exe, c)
			}
		}
	}
	return nil
}

// validateUnquarantine: the §4.6 reverse of quarantine. Target is the
// quarantine-DST (the moved-aside file); it MUST be under the quarantine dir so
// an attacker cannot use unquarantine to chattr -i / mv an arbitrary file. The
// "origin" arg is the absolute path to restore to.
func (g Guards) validateUnquarantine(req Request) error {
	dst := strings.TrimSpace(req.Target)
	if dst == "" {
		return fmt.Errorf("unquarantine: target (quarantine-dst) path is empty")
	}
	if !path.IsAbs(dst) {
		return fmt.Errorf("unquarantine: target %q must be an absolute path", dst)
	}
	qdir := strings.TrimSpace(g.QuarantineDir)
	if qdir == "" {
		qdir = DefaultGuards().QuarantineDir
	}
	if !pathUnder(path.Clean(dst), qdir) {
		return fmt.Errorf("unquarantine: refusing %q — not under the quarantine dir %q", dst, qdir)
	}
	origin := strings.TrimSpace(req.arg("origin"))
	if origin == "" {
		return fmt.Errorf("unquarantine: missing required \"origin\" arg (where to restore the file)")
	}
	if !path.IsAbs(origin) {
		return fmt.Errorf("unquarantine: origin %q must be an absolute path", origin)
	}
	// FIX 1: constrain the restore ORIGIN with a POSITIVE StagingDir allowlist —
	// NOT the quarantine-SOURCE CriticalPaths denylist. The denylist (/proc,/sys,
	// /dev,/bin,/sbin,/usr,/lib*,/boot,/etc,/) is a quarantine-source filter; reused
	// as a restore-destination filter it PERMITS /root/.bashrc,
	// /home/<u>/.ssh/authorized_keys, /var/spool/cron/crontabs/root — so an
	// authenticated socket caller could unquarantine attacker-staged content over a
	// live sensitive file (persistence / code-exec). The ONLY legitimate auto-undo
	// origin (§4.2/G5) is a file that was quarantined FROM a StagingDir; the manual
	// reverse of such a quarantine is likewise staging-resident. So the origin MUST
	// be under a configured StagingDir. (The executor additionally refuses if the
	// origin already EXISTS, so undo can never clobber a live file — that Lstat is
	// I/O and lives at execute time.)
	staging := g.StagingDirs
	if len(staging) == 0 {
		staging = DefaultGuards().StagingDirs
	}
	cleanOrigin := path.Clean(origin)
	for _, d := range staging {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if pathUnder(cleanOrigin, d) && path.Clean(d) != "/" {
			return nil
		}
	}
	return fmt.Errorf("unquarantine: refusing origin %q — not under a configured staging dir %v (restore destinations are allowlist-constrained, not denylist-filtered)", origin, staging)
}

// validateDeIsolate: the §4.6 reverse of isolate (nft delete the isolation
// table). It is inherently safe — RESTORING egress can never self-lock-out — so
// it has no target requirement.
func (g Guards) validateDeIsolate(req Request) error {
	return nil
}

// validateRestoreKey: the §4.6 reverse of revoke-key. Target must be an
// authorized_keys path (validated exactly like revoke-key, minus the fingerprint:
// restore brings the whole file back from its backup).
func (g Guards) validateRestoreKey(req Request) error {
	target := strings.TrimSpace(req.Target)
	if target == "" {
		return fmt.Errorf("restore-key: target path is empty")
	}
	base := path.Base(target)
	if base != "authorized_keys" && base != "authorized_keys2" {
		return fmt.Errorf("restore-key: target %q is not an authorized_keys file", target)
	}
	return nil
}

// splitArgList splits a comma-separated Args value into trimmed, non-empty
// entries (used for quarantine-fd's "staging_dirs" constraint).
func splitArgList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// pathUnder reports whether clean (an already path.Clean'd absolute path) is at
// or below the directory prefix. It compares whole path segments so "/usr"
// matches "/usr" and "/usr/bin/x" but not "/usrlocal/x".
func pathUnder(clean, prefix string) bool {
	prefix = path.Clean(prefix)
	if prefix == "/" {
		return true
	}
	if clean == prefix {
		return true
	}
	return strings.HasPrefix(clean, prefix+"/")
}

// firstSegment returns the first path component of an absolute, cleaned path.
// "/lib64/ld.so" → "lib64"; "/" → "".
func firstSegment(clean string) string {
	trimmed := strings.TrimPrefix(clean, "/")
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		return trimmed[:i]
	}
	return trimmed
}

// isSHA256 reports whether s is exactly 64 lowercase-or-uppercase hex chars.
func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
