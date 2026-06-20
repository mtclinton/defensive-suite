package respond

import (
	"fmt"
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
}

// NewRealExecutor builds a RealExecutor with the given guards.
func NewRealExecutor(g Guards) *RealExecutor {
	return &RealExecutor{Guards: g, IsolateTable: "dsuite_isolate"}
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
	case ActionRevokeKey:
		return e.revokeKey(req)
	case ActionBlockHash:
		return e.blockHash(req)
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
		return Result{Action: req.Action, Target: req.Target}, fmt.Errorf("quarantine move: %w", err)
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
