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
	case ActionRevokeKey:
		return g.validateRevokeKey(req)
	case ActionBlockHash:
		return g.validateBlockHash(req)
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
