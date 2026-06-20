// Package preflight is a strictly READ-ONLY host-readiness verifier for arming
// M4 enforcement. It inspects host state — stats files, reads /boot config,
// runs `--version` / `is-active` / `tetra ... list` probes — and reports
// whether the box is ready to have a Tetragon enforce policy loaded. It NEVER
// mutates anything: it loads no policy, enables no enforcement, and writes no
// sysctl / nftables / fapolicyd rule. Arming is a documented, human-run step
// (see agent/deploy/ENFORCE.md), not something this package performs.
//
// Every probe goes through the injected Runner / FS interfaces, so the whole
// package is unit-testable with fakes: no test ever touches a real
// tetra/nft/fapolicyd binary, /boot, or the Tetragon socket.
package preflight

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Severity ranks how much a not-OK check should worry the operator. It is
// deliberately a small, self-contained enum (not report.Severity) so the
// package has no view into report's iota ordering; ToReport maps it across.
type Severity int

const (
	// SeverityInfo is advisory: a not-OK info check never blocks arming.
	SeverityInfo Severity = iota
	// SeverityMedium is a soft blocker: arming can proceed but a capability is
	// reduced (e.g. Override blocking unavailable; SIGKILL still works).
	SeverityMedium
	// SeverityHigh is a hard blocker: do not arm enforcement until it is OK.
	SeverityHigh
)

var severityNames = map[Severity]string{
	SeverityInfo:   "info",
	SeverityMedium: "medium",
	SeverityHigh:   "high",
}

// String renders the severity as its lowercase name.
func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// Check is one host-readiness probe result. OK=true means the prerequisite is
// satisfied; when OK=false, Severity says how badly, Detail explains what was
// observed, and Remedy says what the operator should do about it.
type Check struct {
	Name     string   // stable identifier, e.g. "kernel-btf"
	OK       bool     // prerequisite satisfied?
	Severity Severity // how bad a not-OK result is (only meaningful when !OK)
	Detail   string   // what was observed
	Remedy   string   // how to fix a not-OK result (empty when OK)
}

// Runner runs a host command and returns its combined output. It is injected so
// tests use a fake; the real impl (RealRunner) shells out read-only — every
// command preflight runs (`nft --version`, `systemctl is-active …`,
// `tetra … list`, `uname -r`) only inspects state, none mutate.
type Runner interface {
	Run(name string, args ...string) (string, error)
}

// FS reads host files read-only. Stat reports existence/metadata; ReadFile
// returns contents. Injected so tests use a fake in-memory FS; the real impl
// (RealFS) calls os.Stat / os.ReadFile — neither writes.
type FS interface {
	Stat(name string) (os.FileInfo, error)
	ReadFile(name string) ([]byte, error)
}

// Env reads environment variables. Injected so response-readiness checks are
// testable without mutating the process environment.
type Env func(string) string

// ----------------------------------------------------------------------------
// Real implementations — used by the `agentd preflight` subcommand. All
// read-only: no exec runs a mutating command, no FS call writes.
// ----------------------------------------------------------------------------

// RealRunner runs commands on the host via os/exec, returning combined output.
type RealRunner struct{}

// Run executes name+args and returns trimmed combined stdout+stderr. A missing
// binary or non-zero exit surfaces as a non-nil error (with whatever output the
// command produced), which the checks treat as "feature absent / inactive".
func (RealRunner) Run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// RealFS reads the host filesystem read-only.
type RealFS struct{}

// Stat reports file metadata (existence) via os.Stat.
func (RealFS) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }

// ReadFile returns file contents via os.ReadFile.
func (RealFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

// Inputs bundles the injected dependencies a Run needs. Zero values are
// replaced with the real, read-only implementations, so callers can pass an
// empty Inputs to probe the live host or a fully-faked one in tests.
type Inputs struct {
	Runner Runner
	FS     FS
	Getenv Env
}

func (in Inputs) runner() Runner {
	if in.Runner != nil {
		return in.Runner
	}
	return RealRunner{}
}

func (in Inputs) fs() FS {
	if in.FS != nil {
		return in.FS
	}
	return RealFS{}
}

func (in Inputs) getenv() Env {
	if in.Getenv != nil {
		return in.Getenv
	}
	return os.Getenv
}

// Run executes every readiness probe and returns the checks in a stable order.
// It is pure with respect to the host: it only stats/reads files and runs
// inspection commands. Nothing here loads a policy, enables enforcement, or
// writes a rule — arming is the operator's job (deploy/ENFORCE.md).
func Run(in Inputs) []Check {
	rt, fs, getenv := in.runner(), in.fs(), in.getenv()

	// kernel release is gathered first so other checks can reference it.
	release := kernelRelease(rt)

	return []Check{
		checkKernelRelease(release),
		checkBTF(fs),
		checkKprobeOverride(fs, release),
		checkNftables(rt),
		checkFapolicyd(rt),
		checkTetragonBinary(rt),
		checkTetragonActive(rt),
		checkTetragonSocket(fs),
		checkEnforcePolicy(rt),
		checkResponseReadiness(getenv),
	}
}

// kernelRelease returns `uname -r` output, or "" if it could not be determined.
func kernelRelease(rt Runner) string {
	out, err := rt.Run("uname", "-r")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// checkKernelRelease reports the running kernel. Informational: it never blocks
// arming, but the release is what selects the /boot/config-<release> file and
// is useful context in the report.
func checkKernelRelease(release string) Check {
	if release == "" {
		return Check{
			Name:     "kernel-release",
			OK:       false,
			Severity: SeverityInfo,
			Detail:   "could not determine kernel release (`uname -r` failed)",
			Remedy:   "ensure `uname` is on PATH; this is informational only",
		}
	}
	return Check{Name: "kernel-release", OK: true, Detail: "kernel " + release}
}

// checkBTF verifies kernel BTF is present. Tetragon's kprobe-based policies need
// BTF to attach reliably, so a missing /sys/kernel/btf/vmlinux is a HARD blocker.
func checkBTF(fs FS) Check {
	const path = "/sys/kernel/btf/vmlinux"
	if _, err := fs.Stat(path); err != nil {
		return Check{
			Name:     "kernel-btf",
			OK:       false,
			Severity: SeverityHigh,
			Detail:   "BTF not found at " + path,
			Remedy:   "boot a kernel built with CONFIG_DEBUG_INFO_BTF=y (most modern distro kernels have it)",
		}
	}
	return Check{Name: "kernel-btf", OK: true, Detail: "BTF present at " + path}
}

// checkKprobeOverride checks CONFIG_BPF_KPROBE_OVERRIDE in the kernel config.
// This is needed ONLY for Tetragon's `Override` blocking (injecting a return
// value, e.g. denying execve). The M4 enforce policy uses `Sigkill`, which works
// WITHOUT this option — so a missing CONFIG_BPF_KPROBE_OVERRIDE is MEDIUM /
// advisory, never a hard blocker for SIGKILL-based enforcement.
//
// It reads /boot/config-<release> first, then falls back to /proc/config.gz
// (gzip magic detected; not decompressed here to stay stdlib-light and because
// presence of the gz already tells us the config is queryable on this host).
func checkKprobeOverride(fs FS, release string) Check {
	const opt = "CONFIG_BPF_KPROBE_OVERRIDE"

	// Primary source: the plaintext /boot/config-<release>.
	if release != "" {
		path := "/boot/config-" + release
		if data, err := fs.ReadFile(path); err == nil {
			if configEnabled(string(data), opt) {
				return Check{Name: "kprobe-override", OK: true, Detail: opt + "=y (from " + path + ")"}
			}
			return Check{
				Name:     "kprobe-override",
				OK:       false,
				Severity: SeverityMedium,
				Detail:   opt + " not enabled in " + path + " — Override blocking unavailable; SIGKILL still works",
				Remedy:   "the M4 enforce policy uses Sigkill (no Override), so this is advisory; only needed if you add an Override action later",
			}
		}
	}

	// Fallback: /proc/config.gz — gzip-compressed kernel config. Decompress it
	// with the stdlib and actually PARSE the option, rather than guessing from the
	// gzip magic. (A few kernels expose it as plaintext; that path is handled too.)
	if data, err := fs.ReadFile("/proc/config.gz"); err == nil {
		text := string(data)
		if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
			if gz, gerr := gzip.NewReader(bytes.NewReader(data)); gerr == nil {
				if dec, derr := io.ReadAll(gz); derr == nil {
					text = string(dec)
				}
				_ = gz.Close()
			}
		}
		if configEnabled(text, opt) {
			return Check{Name: "kprobe-override", OK: true, Detail: opt + "=y (from /proc/config.gz)"}
		}
		return Check{
			Name:     "kprobe-override",
			OK:       false,
			Severity: SeverityMedium,
			Detail:   opt + " not enabled in /proc/config.gz — Override blocking unavailable; SIGKILL still works",
			Remedy:   "advisory only: the M4 enforce policy uses Sigkill, which does not need " + opt,
		}
	}

	return Check{
		Name:     "kprobe-override",
		OK:       false,
		Severity: SeverityMedium,
		Detail:   "could not read kernel config (/boot/config-<release> or /proc/config.gz) to confirm " + opt,
		Remedy:   "advisory only: the M4 enforce policy uses Sigkill, which does not need CONFIG_BPF_KPROBE_OVERRIDE",
	}
}

// configEnabled reports whether a kernel config blob has `OPT=y` (or =m),
// ignoring the commented "# OPT is not set" form.
func configEnabled(config, opt string) bool {
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, opt+"=") {
			v := strings.TrimPrefix(line, opt+"=")
			return v == "y" || v == "m"
		}
	}
	return false
}

// checkNftables verifies the nft binary is present (`nft --version`). nftables
// backs the response isolate actuator and the optional egress baseline, so its
// absence is a MEDIUM (those features won't work; Tetragon enforcement still will).
func checkNftables(rt Runner) Check {
	out, err := rt.Run("nft", "--version")
	if err != nil {
		return Check{
			Name:     "nftables",
			OK:       false,
			Severity: SeverityMedium,
			Detail:   "`nft --version` failed: " + errDetail(err, out),
			Remedy:   "install nftables (needed for network-isolate and the egress baseline; not for Tetragon SIGKILL enforcement)",
		}
	}
	return Check{Name: "nftables", OK: true, Detail: firstLine(out)}
}

// checkFapolicyd verifies fapolicyd is present AND active. It backs the
// block-hash response actuator. Absence/inactive is MEDIUM (block-hash won't
// work; other enforcement is unaffected).
func checkFapolicyd(rt Runner) Check {
	if _, err := rt.Run("fapolicyd", "--version"); err != nil {
		return Check{
			Name:     "fapolicyd",
			OK:       false,
			Severity: SeverityMedium,
			Detail:   "fapolicyd not found",
			Remedy:   "install fapolicyd (needed for the block-hash response actuator)",
		}
	}
	active, detail := isActive(rt, "fapolicyd")
	if !active {
		return Check{
			Name:     "fapolicyd",
			OK:       false,
			Severity: SeverityMedium,
			Detail:   "fapolicyd installed but not active (" + detail + ")",
			Remedy:   "`systemctl enable --now fapolicyd` (review first); needed for block-hash",
		}
	}
	return Check{Name: "fapolicyd", OK: true, Detail: "installed and active"}
}

// checkTetragonBinary verifies the `tetra` CLI is present. Tetragon is the
// enforcement engine for M4, so a missing CLI is a HARD blocker.
func checkTetragonBinary(rt Runner) Check {
	out, err := rt.Run("tetra", "version")
	if err != nil {
		return Check{
			Name:     "tetragon-binary",
			OK:       false,
			Severity: SeverityHigh,
			Detail:   "`tetra version` failed: " + errDetail(err, out),
			Remedy:   "install Tetragon + the `tetra` CLI (see deploy/ENFORCE.md); required for enforcement",
		}
	}
	return Check{Name: "tetragon-binary", OK: true, Detail: firstLine(out)}
}

// checkTetragonActive verifies the tetragon service is active. Without the
// daemon running, no policy can be loaded — HARD blocker.
func checkTetragonActive(rt Runner) Check {
	active, detail := isActive(rt, "tetragon")
	if !active {
		return Check{
			Name:     "tetragon-active",
			OK:       false,
			Severity: SeverityHigh,
			Detail:   "tetragon service not active (" + detail + ")",
			Remedy:   "`systemctl enable --now tetragon` (review first); required before loading any policy",
		}
	}
	return Check{Name: "tetragon-active", OK: true, Detail: "tetragon service active"}
}

// checkTetragonSocket verifies the Tetragon gRPC socket exists. agentd consumes
// events here; without it the daemon may be mid-start. HARD blocker.
func checkTetragonSocket(fs FS) Check {
	const sock = "/var/run/tetragon/tetragon.sock"
	if _, err := fs.Stat(sock); err != nil {
		return Check{
			Name:     "tetragon-socket",
			OK:       false,
			Severity: SeverityHigh,
			Detail:   "Tetragon socket not found at " + sock,
			Remedy:   "ensure Tetragon is running with its gRPC server enabled (default socket)",
		}
	}
	return Check{Name: "tetragon-socket", OK: true, Detail: "socket present at " + sock}
}

// checkEnforcePolicy reports whether any enforce TracingPolicy is already
// loaded (`tetra tracingpolicy list`). This is INFORMATIONAL: it tells the
// operator the current arming state. It does NOT load or change anything. If a
// policy whose name suggests enforcement is present, that is surfaced so the
// operator knows the host may already be armed.
func checkEnforcePolicy(rt Runner) Check {
	out, err := rt.Run("tetra", "tracingpolicy", "list")
	if err != nil {
		return Check{
			Name:     "enforce-policy",
			OK:       true, // not a blocker: we just couldn't enumerate policies
			Severity: SeverityInfo,
			Detail:   "could not list TracingPolicies (`tetra tracingpolicy list` failed): " + errDetail(err, out),
			Remedy:   "informational; ensure the Tetragon daemon is reachable to enumerate loaded policies",
		}
	}
	loaded := loadedPolicyNames(out)
	if len(loaded) == 0 {
		return Check{
			Name:     "enforce-policy",
			OK:       true,
			Severity: SeverityInfo,
			Detail:   "no TracingPolicies loaded — host is unarmed (observe and enforce both absent)",
		}
	}
	enforce := false
	for _, n := range loaded {
		if strings.Contains(strings.ToLower(n), "enforce") {
			enforce = true
		}
	}
	detail := "loaded TracingPolicies: " + strings.Join(loaded, ", ")
	if enforce {
		detail += " (an enforce-named policy is present — host may already be armed)"
	}
	return Check{Name: "enforce-policy", OK: true, Severity: SeverityInfo, Detail: detail}
}

// checkResponseReadiness reports whether the manual-response path is configured.
// Advisory: AGENT_RESPONSE_TOKEN must be set for the response socket to serve,
// and --enable-response (or AGENT_ENABLE_RESPONSE) flips it out of dry-run. This
// only READS the environment; it never enables anything.
func checkResponseReadiness(getenv Env) Check {
	tokenSet := strings.TrimSpace(getenv("AGENT_RESPONSE_TOKEN")) != ""
	enableSet := truthy(getenv("AGENT_ENABLE_RESPONSE"))

	switch {
	case !tokenSet:
		return Check{
			Name:     "response-readiness",
			OK:       false,
			Severity: SeverityInfo,
			Detail:   "AGENT_RESPONSE_TOKEN not set — the response socket cannot serve (fails closed)",
			Remedy:   "set AGENT_RESPONSE_TOKEN (env-only) to arm manual response; see deploy/RESPONSE.md",
		}
	case !enableSet:
		return Check{
			Name:     "response-readiness",
			OK:       true,
			Severity: SeverityInfo,
			Detail:   "AGENT_RESPONSE_TOKEN set; response stays DRY-RUN until --enable-response (or AGENT_ENABLE_RESPONSE) is given",
		}
	default:
		return Check{
			Name:     "response-readiness",
			OK:       true,
			Severity: SeverityInfo,
			Detail:   "AGENT_RESPONSE_TOKEN set and AGENT_ENABLE_RESPONSE truthy — response would be LIVE once a socket is served",
		}
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

// isActive runs `systemctl is-active <unit>` and reports whether it printed
// "active". systemctl exits non-zero for inactive units, so a non-nil error
// with "inactive"/"unknown" output is the normal not-active path.
func isActive(rt Runner, unit string) (bool, string) {
	out, _ := rt.Run("systemctl", "is-active", unit)
	state := firstLine(strings.TrimSpace(out))
	return state == "active", state
}

// loadedPolicyNames extracts policy names from `tetra tracingpolicy list`
// output. The CLI's exact format varies by version, so this is intentionally
// forgiving: it pulls the first whitespace-delimited token from each non-header,
// non-empty line. Empty output → no policies.
func loadedPolicyNames(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		// skip an obvious header row
		if strings.HasPrefix(lower, "name") || strings.HasPrefix(lower, "id ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		names = append(names, fields[0])
	}
	return names
}

// firstLine returns the first line of s (version banners are multi-line).
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// errDetail builds a short detail string from an error and any command output.
func errDetail(err error, out string) string {
	if out != "" {
		return firstLine(out)
	}
	if err != nil {
		return err.Error()
	}
	return "no output"
}

// truthy mirrors config.truthy without importing it (preflight stays leaf-level):
// 1/true/yes/on (any case) → true.
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
