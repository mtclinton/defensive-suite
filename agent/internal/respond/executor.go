package respond

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Executor performs the actual side effect of a validated Request and reports
// what it did. It is an interface so the destructive RealExecutor and the inert
// FakeExecutor are swappable: every test uses FakeExecutor, and RealExecutor is
// never invoked in tests or in this build-and-unit-test environment.
type Executor interface {
	Execute(Request) (Result, error)
}

// ----------------------------------------------------------------------------
// FakeExecutor — records calls, performs NO side effects. The default in tests.
// ----------------------------------------------------------------------------

// FakeExecutor records every Execute call and returns a canned, successful
// Result without touching the system. A test may set Err to force a failure, or
// ResultFn to fully shape the returned Result.
type FakeExecutor struct {
	mu       sync.Mutex
	Calls    []Request
	Err      error
	ResultFn func(Request) Result
}

// Execute records req and returns a synthetic Result (or FakeExecutor.Err).
func (f *FakeExecutor) Execute(req Request) (Result, error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, req)
	f.mu.Unlock()
	if f.Err != nil {
		return Result{Action: req.Action, Target: req.Target}, f.Err
	}
	if f.ResultFn != nil {
		return f.ResultFn(req), nil
	}
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: "fake: " + req.String(),
		Undo:   "fake-undo",
	}, nil
}

// CallCount returns how many times Execute was invoked.
func (f *FakeExecutor) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Calls)
}

// Last returns the most recent recorded Request and whether one exists.
func (f *FakeExecutor) Last() (Request, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.Calls) == 0 {
		return Request{}, false
	}
	return f.Calls[len(f.Calls)-1], true
}

// ----------------------------------------------------------------------------
// RealExecutor — the privileged, side-effecting implementation. SHIPPED, but
// NEVER invoked in tests or in the build-and-unit-test environment. It is only
// reached when the agent runs with --enable-response on a real host.
// ----------------------------------------------------------------------------

// RealExecutor performs the genuine system actions (syscall.Kill, nft, chattr,
// authorized_keys edits, fapolicyd rules). Guards is its own copy so it knows
// the quarantine dir / mgmt ifaces; it re-validates each request as defence in
// depth even though the Responder already validated.
type RealExecutor struct {
	Guards Guards
	// IsolateTable is the nftables table name used for egress isolation.
	IsolateTable string
	// proc re-resolves live process identity for the §3.2/§4.2 fd-based quarantine.
	// It is READ-ONLY (resolve() never acts). Defaults to the real /proc resolver;
	// injectable so a test can drive the identity-bind logic against a fabricated
	// /proc snapshot without a real process.
	proc procResolver
}

// NewRealExecutor builds a RealExecutor with the given guards.
func NewRealExecutor(g Guards) *RealExecutor {
	return &RealExecutor{Guards: g, IsolateTable: "dsuite_isolate", proc: realProcResolver{}}
}

// Execute dispatches to the per-action implementation. It re-runs Validate so a
// RealExecutor used directly still enforces the guardrails.
func (e *RealExecutor) Execute(req Request) (Result, error) {
	if err := e.Guards.Validate(req); err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	switch req.Action {
	case ActionKill:
		return e.kill(req)
	case ActionIsolate:
		return e.isolate(req)
	case ActionQuarantine:
		return e.quarantine(req)
	case ActionQuarantineFD:
		return e.quarantineFD(req)
	case ActionRevokeKey:
		return e.revokeKey(req)
	case ActionBlockHash:
		return e.blockHash(req)
	case ActionUnquarantine:
		return e.unquarantine(req)
	case ActionDeIsolate:
		return e.deIsolate(req)
	case ActionRestoreKey:
		return e.restoreKey(req)
	default:
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("unknown action %q", req.Action)
	}
}

func (e *RealExecutor) kill(req Request) (Result, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(req.Target))
	if err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	// SIGKILL the process. (A real tree-kill would resolve children first; kept
	// to the single PID here — irreversible either way.)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("kill %d: %w", pid, err)
	}
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: fmt.Sprintf("sent SIGKILL to pid %d", pid),
		Undo:   "", // killing a process is not reversible
	}, nil
}

func (e *RealExecutor) isolate(req Request) (Result, error) {
	table := e.IsolateTable
	if table == "" {
		table = "dsuite_isolate"
	}
	// Install an nftables table whose output chain DROPS by default, then ACCEPT
	// only the lifeline interfaces: loopback plus the configured management
	// interfaces (SSH/Tailscale). Everything else is cut. This is the design's
	// "drop all egress except the management interface" — the kept set is the
	// mgmt ifaces, NOT req.Target (the network being isolated), so isolating a
	// host can never drop the operator's own access. A bare drop policy with no
	// accept rule (the earlier form) would have cut EVERYTHING, including the
	// interface it claimed to keep. Reversible: delete the table.
	if err := run("nft", "add", "table", "inet", table); err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	if err := run("nft", "add", "chain", "inet", table, "output",
		"{ type filter hook output priority 0 ; policy drop ; }"); err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	keep := append([]string{"lo"}, e.Guards.MgmtIfaces...)
	seen := map[string]bool{}
	var kept []string
	for _, k := range keep {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		if err := run("nft", "add", "rule", "inet", table, "output",
			"oifname", k, "accept"); err != nil {
			return Result{Action: req.Action, Target: req.Target}, err
		}
		kept = append(kept, k)
	}
	undo := fmt.Sprintf("nft delete table inet %s", table)
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: fmt.Sprintf("isolated %q: egress dropped except %v", req.Target, kept),
		Undo:   undo,
	}, nil
}

func (e *RealExecutor) quarantine(req Request) (Result, error) {
	src := strings.TrimSpace(req.Target)
	dir := e.Guards.QuarantineDir
	if dir == "" {
		dir = DefaultGuards().QuarantineDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	dst := filepath.Join(dir, fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(src)))
	if err := os.Rename(src, dst); err != nil {
		// os.Rename fails with EXDEV across filesystems (e.g. a file staged in /tmp
		// (tmpfs) and the quarantine dir on the root fs). Fall back to copy+remove
		// so quarantine works across mounts; any other error is fatal.
		if errors.Is(err, syscall.EXDEV) {
			if cerr := copyThenRemove(src, dst); cerr != nil {
				return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("quarantine copy: %w", cerr)
			}
		} else {
			return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("quarantine move: %w", err)
		}
	}
	// Make the quarantined copy immutable + unreadable. Best-effort: a failure to
	// lock down does not undo the move.
	_ = run("chattr", "+i", dst)
	_ = os.Chmod(dst, 0o000)
	undo := fmt.Sprintf("chattr -i %q && mv %q %q", dst, dst, src)
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: fmt.Sprintf("moved to %q (chattr +i, chmod 000)", dst),
		Undo:   undo,
	}, nil
}

func (e *RealExecutor) revokeKey(req Request) (Result, error) {
	path := strings.TrimSpace(req.Target)
	fp := strings.TrimSpace(req.arg("fingerprint"))
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	// Back the file up first (the Undo). Refuse to empty the file.
	backup := path + ".dsuite.bak"
	if err := os.WriteFile(backup, data, 0o600); err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	lines := strings.Split(string(data), "\n")
	var kept []string
	removed := 0
	for _, ln := range lines {
		if strings.Contains(ln, fp) {
			removed++
			continue
		}
		kept = append(kept, ln)
	}
	if removed == 0 {
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("revoke-key: no line matching fingerprint %q in %q", fp, path)
	}
	out := strings.Join(kept, "\n")
	if strings.TrimSpace(out) == "" {
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("revoke-key: refusing to empty %q (backup kept at %q)", path, backup)
	}
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	undo := fmt.Sprintf("cp %q %q", backup, path)
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: fmt.Sprintf("removed %d key line(s) matching %q (backup %q)", removed, fp, backup),
		Undo:   undo,
	}, nil
}

func (e *RealExecutor) blockHash(req Request) (Result, error) {
	hash := strings.ToLower(strings.TrimSpace(req.Target))
	// fapolicyd deny rule by sha256. Reversible by removing the rule line.
	rule := fmt.Sprintf("deny perm=execute all : sha256hash=%s", hash)
	dir := "/etc/fapolicyd/rules.d"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	rulePath := filepath.Join(dir, "90-dsuite-"+hash[:12]+".rules")
	if err := os.WriteFile(rulePath, []byte(rule+"\n"), 0o644); err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	// Reload fapolicyd so the rule takes effect.
	_ = run("fapolicyd-cli", "--update")
	undo := fmt.Sprintf("rm %q && fapolicyd-cli --update", rulePath)
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: fmt.Sprintf("fapolicyd deny rule %q", rulePath),
		Undo:   undo,
	}, nil
}

// quarantineFD is the §3.2/§4.2 identity-bound, fd-based quarantine. Unlike the
// lexical `quarantine`, it NEVER trusts a path string as the target: it
// re-resolves the LIVE process from /proc, REQUIRES it to still be alive with a
// matching (exec_id, starttime) identity AND a realpath resident UNDER a
// configured StagingDir, then opens the file O_NOFOLLOW and acts BY FD (fstat on
// the same fd it will move) so the file checked is the file acted on — closing the
// TOCTOU split. Any identity mismatch, dead process, or out-of-staging realpath is
// REFUSED. (The fd is used to fstat-confirm the inode before the move; the move
// itself is by the confirmed realpath, which O_NOFOLLOW + the staging re-check
// have bound to the live process.)
func (e *RealExecutor) quarantineFD(req Request) (Result, error) {
	resolver := e.proc
	if resolver == nil {
		resolver = realProcResolver{}
	}
	pid, err := strconv.Atoi(strings.TrimSpace(req.Target))
	if err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	wantStart, err := strconv.ParseUint(strings.TrimSpace(req.arg("starttime")), 10, 64)
	if err != nil {
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("quarantine-fd: bad starttime arg: %w", err)
	}
	staging := splitArgList(req.arg("staging_dirs"))

	// RE-RESOLVE live identity. A dead/reused process or a starttime/exec_id
	// mismatch means the process we attributed at detection is gone — REFUSE rather
	// than act on a different inode.
	info := resolver.resolve(pid)
	if !info.Live {
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("quarantine-fd: pid %d is no longer live (refusing)", pid)
	}
	if info.StartTime != wantStart {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("quarantine-fd: identity mismatch for pid %d (starttime %d != captured %d) — refusing", pid, info.StartTime, wantStart)
	}
	if wantExec := strings.TrimSpace(req.arg("exec_id")); wantExec != "" && info.ExecID != "" && info.ExecID != wantExec {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("quarantine-fd: identity mismatch for pid %d (exec_id) — refusing", pid)
	}
	// REQUIRE the live exe to be resident under a configured StagingDir. A forged
	// finding naming /opt/... cannot match a staging-resident live process.
	if !underStagingDir(info.Exe, staging) {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("quarantine-fd: live exe %q is not under a staging dir %v — refusing", info.Exe, staging)
	}

	// Open the resolved exe O_NOFOLLOW so a swapped-in symlink cannot redirect us,
	// and fstat the fd to confirm we hold the inode we checked. We then move by the
	// confirmed realpath. (A fileless/deleted image has no on-disk path to open; the
	// staging residency + identity bind already gate it, and there is nothing to move
	// — report that explicitly rather than failing opaquely.)
	src := info.Exe
	f, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("quarantine-fd: open %q O_NOFOLLOW: %w (deleted/fileless image or symlink — refusing)", src, err)
	}
	var st syscall.Stat_t
	if ferr := syscall.Fstat(int(f.Fd()), &st); ferr != nil {
		_ = f.Close()
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("quarantine-fd: fstat %q: %w", src, ferr)
	}
	_ = f.Close()

	dir := e.Guards.QuarantineDir
	if dir == "" {
		dir = DefaultGuards().QuarantineDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{Action: req.Action, Target: req.Target}, err
	}
	dst := filepath.Join(dir, fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(src)))
	if err := renameFn(src, dst); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			// FIX 4 (cross-fs branch): a copy makes a NEW inode, so a post-move
			// inode compare is meaningless. Instead RE-CONFIRM the source inode by
			// fd immediately before copying — if src no longer holds the fstat'd
			// (Ino,Dev) it was swapped between check and act, so REFUSE without
			// touching it.
			if cerr := copyConfirmedInode(src, dst, st); cerr != nil {
				return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("quarantine-fd copy: %w", cerr)
			}
		} else {
			return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("quarantine-fd move: %w", err)
		}
	} else {
		// FIX 4 (rename branch): os.Rename moved a PATH STRING after we closed the
		// fstat'd fd, so the inode validated is not PROVABLY the inode moved
		// (TOCTOU; checked != acted, §4.2 #17). Re-fstat the MOVED file by fd
		// (O_NOFOLLOW) and compare (Ino,Dev) to the pre-move values. On mismatch an
		// attacker swapped the target between check and act: ROLL BACK (move it back
		// to src) and REFUSE so we never lock down the wrong inode.
		if merr := confirmMovedInode(dst, st); merr != nil {
			if rberr := os.Rename(dst, src); rberr != nil {
				return Result{Action: req.Action, Target: req.Target},
					fmt.Errorf("quarantine-fd: %v; ROLLBACK FAILED (%v) — %q now at %q", merr, rberr, src, dst)
			}
			return Result{Action: req.Action, Target: req.Target},
				fmt.Errorf("quarantine-fd: %w (rolled back to %q)", merr, src)
		}
	}
	_ = run("chattr", "+i", dst)
	_ = os.Chmod(dst, 0o000)
	// The structured inverse is an ActionUnquarantine Request (Target=dst,
	// origin=src); the free-text string is the human-readable note.
	undo := fmt.Sprintf("chattr -i %q && mv %q %q", dst, dst, src)
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: fmt.Sprintf("identity-bound quarantine of pid %d exe %q (inode %d) → %q (chattr +i, chmod 000)", pid, src, st.Ino, dst),
		Undo:   undo,
	}, nil
}

// unquarantine is the §4.6 reverse of quarantine: chattr -i the quarantined copy,
// then mv it back to its recorded origin. Target is the quarantine-dst, the
// "origin" arg the path to restore to. (Validate already bound the dst under the
// quarantine dir and the origin to a permitted path.)
func (e *RealExecutor) unquarantine(req Request) (Result, error) {
	dst := strings.TrimSpace(req.Target)
	origin := strings.TrimSpace(req.arg("origin"))

	// FIX 2 (checked FIRST): refuse a SYMLINKED final component of the origin's
	// PARENT — a pre-planted symlink (e.g. /staging/.ssh -> /root/.ssh, or the
	// origin's leaf dir being a symlink to a privileged dir) would otherwise
	// redirect the rename to a privileged location. This is checked BEFORE the
	// exists check so an attacker cannot bypass the symlink guard by pointing the
	// parent symlink at a NON-existent privileged leaf (which would pass an
	// exists-check and let the rename CREATE a file in the privileged dir). Lstat
	// the parent and refuse if it is a symlink. Mirror quarantineFD's O_NOFOLLOW
	// discipline on the reverse path.
	parent := filepath.Dir(origin)
	if pinfo, perr := os.Lstat(parent); perr != nil {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("unquarantine: cannot stat origin parent %q: %w (refusing)", parent, perr)
	} else if pinfo.Mode()&os.ModeSymlink != 0 {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("unquarantine: origin parent %q is a symlink — refusing (would redirect the restore)", parent)
	}

	// FIX 1: REFUSE if the origin already exists — undo must never CLOBBER a live
	// file. (Validate constrained the origin to a StagingDir, but a live file may
	// have appeared at that path since; a quarantine of X then a recreated X must
	// not be silently overwritten by the restore.) Lstat (not Stat) so a symlink
	// AT the origin counts as "exists" and is refused, not followed.
	if _, lerr := os.Lstat(origin); lerr == nil {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("unquarantine: origin %q already exists — refusing to clobber a live file", origin)
	} else if !os.IsNotExist(lerr) {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("unquarantine: cannot stat origin %q: %w (refusing)", origin, lerr)
	}

	// chmod back to readable before the move (the quarantine set it 000) and drop
	// the immutable bit; both best-effort, then the move is the load-bearing step.
	_ = run("chattr", "-i", dst)
	_ = os.Chmod(dst, 0o600)
	if err := os.Rename(dst, origin); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			if cerr := copyThenRemoveNoFollow(dst, origin); cerr != nil {
				return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("unquarantine copy: %w", cerr)
			}
		} else {
			return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("unquarantine move: %w", err)
		}
	}
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: fmt.Sprintf("restored %q → %q (chattr -i)", dst, origin),
		Undo:   "", // its own inverse is to re-quarantine
	}, nil
}

// deIsolate is the §4.6 reverse of isolate: delete the nftables isolation table,
// lifting the host-wide egress drop. Best-effort like isolate; a failed delete is
// surfaced as an error so a half-isolated host is loud, not silent.
func (e *RealExecutor) deIsolate(req Request) (Result, error) {
	table := e.IsolateTable
	if table == "" {
		table = "dsuite_isolate"
	}
	if err := run("nft", "delete", "table", "inet", table); err != nil {
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("de-isolate: %w", err)
	}
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: fmt.Sprintf("deleted nftables table inet %s (egress restored)", table),
		Undo:   "", // its own inverse is to re-isolate
	}, nil
}

// restoreKey is the §4.6 reverse of revoke-key: restore authorized_keys from its
// .dsuite.bak backup. Target is the authorized_keys path; the backup is the same
// .dsuite.bak revoke-key wrote.
func (e *RealExecutor) restoreKey(req Request) (Result, error) {
	keyPath := strings.TrimSpace(req.Target)
	backup := keyPath + ".dsuite.bak"
	data, err := os.ReadFile(backup)
	if err != nil {
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("restore-key: read backup %q: %w", backup, err)
	}

	// FIX 2: do NOT os.WriteFile the destination — that FOLLOWS a symlink at the
	// path, so a pre-planted authorized_keys symlink (e.g. /staging/.ssh/
	// authorized_keys -> /root/.ssh/authorized_keys) would redirect the write to a
	// privileged file (SSH-key implantation). Mirror quarantineFD's O_NOFOLLOW
	// discipline: Lstat the final component first and refuse a symlink, then open
	// O_WRONLY|O_CREATE|O_TRUNC|O_NOFOLLOW and write BY FD so the file checked is the
	// file written. O_NOFOLLOW alone refuses a symlinked leaf at open time; the
	// pre-Lstat gives a precise refusal and also covers the (impossible-under-
	// O_NOFOLLOW but defensive) race.
	if li, lerr := os.Lstat(keyPath); lerr == nil {
		if li.Mode()&os.ModeSymlink != 0 {
			return Result{Action: req.Action, Target: req.Target},
				fmt.Errorf("restore-key: target %q is a symlink — refusing (would redirect the write)", keyPath)
		}
	} else if !os.IsNotExist(lerr) {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("restore-key: cannot stat target %q: %w (refusing)", keyPath, lerr)
	}
	f, oerr := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if oerr != nil {
		return Result{Action: req.Action, Target: req.Target},
			fmt.Errorf("restore-key: open %q O_NOFOLLOW: %w (symlink — refusing)", keyPath, oerr)
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("restore-key: write %q: %w", keyPath, werr)
	}
	return Result{
		OK:     true,
		Action: req.Action,
		Target: req.Target,
		Detail: fmt.Sprintf("restored %q from %q", keyPath, backup),
		Undo:   "", // its own inverse is to re-revoke
	}, nil
}

// run executes a system command, capturing combined output into any error so the
// failure is diagnosable. It is the single os/exec choke point for RealExecutor.
// It is a var so a test can substitute a recorder that captures the intended
// commands WITHOUT executing them — RealExecutor still performs no real action in
// tests; the default below is the only thing that ever shells out.
var run = func(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// renameFn is the rename used by quarantineFD's forward move. It is a var (default
// os.Rename) ONLY so a FIX 4 test can perform a genuine inode SWAP in the TOCTOU
// window between the fstat-confirmed open and the move, proving the post-move
// inode confirm detects it and rolls back. Production always uses os.Rename;
// nothing else overrides it.
var renameFn = os.Rename

// copyThenRemove moves a file ACROSS filesystems (where os.Rename returns EXDEV):
// copy contents to dst, then remove src. On a copy failure dst is cleaned up and
// src is left intact. Used by quarantine when the target and the quarantine dir
// are on different mounts (e.g. malware staged in /tmp (tmpfs) → /var/lib).
func copyThenRemove(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = in.Close()
		return err
	}
	_, cerr := io.Copy(out, in)
	_ = in.Close()
	if closeErr := out.Close(); cerr == nil {
		cerr = closeErr
	}
	if cerr != nil {
		_ = os.Remove(dst)
		return cerr
	}
	return os.Remove(src)
}

// copyThenRemoveNoFollow is the cross-filesystem fallback for the REVERSE
// actuators (FIX 2): it opens the DESTINATION with O_CREATE|O_EXCL|O_NOFOLLOW so a
// pre-planted symlink at dst cannot redirect the write to a privileged file, and
// O_EXCL guarantees we never clobber an existing file (the dst must not exist —
// the caller already refused an existing origin). On any copy failure the partial
// dst is removed and src is left intact.
func copyThenRemoveNoFollow(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = in.Close()
		return fmt.Errorf("open dst O_NOFOLLOW|O_EXCL: %w", err)
	}
	_, cerr := io.Copy(out, in)
	_ = in.Close()
	if closeErr := out.Close(); cerr == nil {
		cerr = closeErr
	}
	if cerr != nil {
		_ = os.Remove(dst)
		return cerr
	}
	return os.Remove(src)
}

// confirmMovedInode (FIX 4, rename branch) re-opens the just-moved file at dst
// O_NOFOLLOW, fstats it BY FD, and confirms its (Ino,Dev) equals the pre-move
// values fstat'd from the source fd — proving the inode we checked is the inode we
// moved (checked==acted, §4.2 #17). A mismatch means the target was swapped
// between the check (fstat) and the act (rename); an error means we cannot prove
// identity. Either way it returns non-nil and the caller rolls back + refuses.
// confirmMovedInode re-opens the moved file O_NOFOLLOW and refuses unless its
// (Ino,Dev) still equals the pre-move fstat — catching a swap where the attacker
// substituted a DIFFERENT-inode file between check and act (the common case).
//
// RESIDUAL (honest): the (Ino,Dev) NUMBER compare does NOT defend against inode
// REUSE — a local attacker who, in the race window, frees the checked inode and
// gets the SAME inode number reallocated to a substituted file passes this check.
// The fully TOCTOU-safe move is linkat(AT_EMPTY_PATH) from the held O_NOFOLLOW/
// O_PATH fd into the quarantine dir (links the EXACT validated inode, immune to
// path swaps AND number reuse; needs CAP_DAC_READ_SEARCH) — a Linux-only hardening
// deferred to the live-canary gate (see PHASE4_DESIGN.md). This best-effort
// number-compare is strictly better than the prior act-by-path-after-close (which
// confirmed nothing); it is acceptable here only because quarantineFD is STAGED,
// never auto-fired in this build.
func confirmMovedInode(dst string, want syscall.Stat_t) error {
	f, err := os.OpenFile(dst, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("re-open moved file %q O_NOFOLLOW: %w (cannot confirm checked==acted)", dst, err)
	}
	var got syscall.Stat_t
	ferr := syscall.Fstat(int(f.Fd()), &got)
	_ = f.Close()
	if ferr != nil {
		return fmt.Errorf("re-fstat moved file %q: %w (cannot confirm checked==acted)", dst, ferr)
	}
	if got.Ino != want.Ino || got.Dev != want.Dev {
		return fmt.Errorf("inode swap detected between check and act (moved inode %d/%d != checked %d/%d) — refusing",
			got.Ino, got.Dev, want.Ino, want.Dev)
	}
	return nil
}

// copyConfirmedInode (FIX 4, cross-fs branch) re-opens src O_NOFOLLOW, fstats it
// BY FD, and refuses unless its (Ino,Dev) still equals the pre-move values — so a
// target swapped between check and act is detected before any copy. It then copies
// FROM THAT EXACT FD (not by re-resolving the path) into a fresh O_EXCL|O_NOFOLLOW
// dst, and only then removes src. A copy on a different filesystem necessarily
// produces a new inode, so the post-move inode compare used by the rename branch
// cannot apply here; confirming the source inode by fd before copying gives the
// equivalent checked==acted guarantee for this branch.
func copyConfirmedInode(src, dst string, want syscall.Stat_t) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("re-open src %q O_NOFOLLOW: %w (cannot confirm checked==acted)", src, err)
	}
	var got syscall.Stat_t
	if ferr := syscall.Fstat(int(in.Fd()), &got); ferr != nil {
		_ = in.Close()
		return fmt.Errorf("re-fstat src %q: %w (cannot confirm checked==acted)", src, ferr)
	}
	if got.Ino != want.Ino || got.Dev != want.Dev {
		_ = in.Close()
		return fmt.Errorf("inode swap detected between check and act (src inode %d/%d != checked %d/%d) — refusing",
			got.Ino, got.Dev, want.Ino, want.Dev)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = in.Close()
		return fmt.Errorf("open dst O_NOFOLLOW|O_EXCL: %w", err)
	}
	_, cerr := io.Copy(out, in)
	_ = in.Close()
	if closeErr := out.Close(); cerr == nil {
		cerr = closeErr
	}
	if cerr != nil {
		_ = os.Remove(dst)
		return cerr
	}
	return os.Remove(src)
}
