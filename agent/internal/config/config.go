// Package config holds agentd's runtime settings, from defaults overlaid with
// AGENT_* environment variables. agentd consumes Tetragon's JSON event export
// and forwards derived findings to the collector; the collector auth token is
// env-only (never a flag).
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is agentd's settings.
type Config struct {
	// TetragonLog is the Tetragon JSON event export to tail (one JSON object per line).
	TetragonLog string
	// CollectorURL is the collector's /ingest endpoint. Blank disables forwarding.
	CollectorURL string
	// CollectorAuth is the Authorization header value (e.g. "Bearer …"); env-only.
	CollectorAuth string
	// Host labels the reports; defaults to the hostname.
	Host string
	// FlushInterval is how often the rolling finding set is POSTed in `run` mode.
	FlushInterval time.Duration
	// BufferMax caps the rolling finding set (current real-time posture).
	BufferMax int
	// StateDir is agentd's persistent state directory. The tail checkpoint lives
	// at <dir>/tail.state and the delivery spool at <dir>/spool/. Created at
	// runtime; defaults to /var/lib/agentd. AGENT_STATE_DIR overrides it.
	StateDir string

	// StagingDirs: an exec whose binary is under one of these is suspicious.
	StagingDirs []string
	// SensitivePaths: a kprobe write touching one of these (exact file, or a dir
	// entry ending in "/") is a trust-path tamper.
	SensitivePaths []string
	// BPFLoaderAllowlist: binaries permitted to load eBPF programs (empty = flag all).
	BPFLoaderAllowlist []string
	// BPFLoadFuncs: kprobe function names that indicate an eBPF program load.
	BPFLoadFuncs []string
	// WriteFuncs: kprobe function names whose path argument is a written file.
	WriteFuncs []string

	// --- M3 manual response (all default to the SAFE state) ---

	// ResponseSocket is the unix socket agentd serves /respond on. Empty = the
	// response surface is not started.
	ResponseSocket string
	// ResponseToken is the bearer token required to POST /respond; env-only
	// (never a flag, so it isn't visible in the process table). Empty = the
	// response surface fails closed.
	ResponseToken string
	// ResponseEnabled is the master switch. It defaults FALSE; while false, the
	// Responder stays in DryRun and NO destructive action ever reaches the
	// executor. Only an explicit AGENT_ENABLE_RESPONSE=1 / --enable-response
	// flips it on.
	ResponseEnabled bool
	// MgmtIfaces are the management/keep-up interfaces isolate must never drop
	// (would self-lock-out). Always includes loopback.
	MgmtIfaces []string
	// QuarantineDir is where the quarantine actuator moves files.
	QuarantineDir string
	// ResponseMaxBody bounds a /respond request body.
	ResponseMaxBody int64

	// --- M3 response BRAKES (on the weaponizable primitive) ---

	// ResponseKillSwitch is a file path that, when it EXISTS, globally disarms ALL
	// response actions (live and dry-run alike) without restarting agentd. An
	// operator `touch`es it to instantly disable response. Default
	// /run/agentd/response.disabled. The Responder checks it right after guard
	// validation, on every request.
	ResponseKillSwitch string
	// ResponseRateMax caps how many LIVE response executions may run within
	// ResponseRateWindow (sliding window). Beyond the cap, requests are refused and
	// audited so a hijacked response surface cannot become a rapid mass-kill /
	// mass-isolate DoS. Dry-run is free (never counted). 0 disables the limit.
	ResponseRateMax int
	// ResponseRateWindow is the sliding window over which ResponseRateMax applies.
	ResponseRateWindow time.Duration

	// --- Phase 4 AUTO-RESPONSE (decision layer only; NEVER executes in this
	// build). All defaults are SAFE: mode off, and any unparseable value falls
	// back to off/safe. canary/armed are NOT buildable yet — the run/preflight
	// paths hard-error on them and the bridge clamps to shadow. ---

	// AutoResponseMode selects the auto-response ladder rung: off|dry-run|shadow
	// (and the not-yet-implemented canary|armed). Default off → Consider is a
	// no-op. Unparseable → off.
	AutoResponseMode string
	// AutoResponseRateMax / AutoResponseRateWindow are the AUTO path's OWN rate
	// budget (separate from the manual ResponseRate*), default 3/300s. On
	// exhaustion the auto path throttles (emits one throttled finding per window)
	// — it NEVER touches the shared manual kill-switch.
	AutoResponseRateMax    int
	AutoResponseRateWindow time.Duration
	// AutoResponseDisabled is the AUTO-ONLY disarm latch path. When this file
	// EXISTS the auto decision path is throttled (alert-only). It is DISTINCT from
	// ResponseKillSwitch (which is operator-only and disarms MANUAL response too);
	// the auto path must never trip the shared switch. Default
	// /run/agentd/autoresponse.disabled.
	AutoResponseDisabled string
	// AutoStaleTTL is the G6 event-time freshness cutoff: a correlated finding
	// whose Tetragon event time is older than this (vs the clock) is not auto-
	// eligible. Default 5s.
	AutoStaleTTL time.Duration
	// AutoNeverQuarantine is the operator-extendable never-touch denylist of
	// realpaths (or path prefixes) the auto path must never select as a target,
	// beyond the built-in protected set.
	AutoNeverQuarantine []string
	// AutoProtectedPaths overrides the built-in protected-process set: ABSOLUTE
	// on-disk paths (sshd/collector/login shells/systemd at their canonical
	// locations) the auto path must never select as a target. Empty → the built-in
	// defaults. Anchored to real paths, NOT attacker-choosable basenames, so a
	// staging-resident dropper merely NAMED "bash" is not protected.
	AutoProtectedPaths []string
	// MgmtSubnets are CIDRs (in addition to RFC1918/CGNAT/link-local/loopback)
	// the G7 destination-class gate treats as NON-external (ineligible for auto).
	MgmtSubnets []string
}

// Defaults returns a safe baseline for a single Linux workstation.
func Defaults() Config {
	host, _ := os.Hostname()
	return Config{
		TetragonLog:   "/var/log/tetragon/tetragon.log",
		Host:          host,
		FlushInterval: 10 * time.Second,
		BufferMax:     5000,
		StateDir:      "/var/lib/agentd",
		StagingDirs:   []string{"/tmp/", "/dev/shm/", "/var/tmp/"},
		SensitivePaths: []string{
			// --- high-fidelity trust paths (rule emits Critical) ---
			// Almost never legitimately written; a write here is high-confidence.
			"/etc/ld.so.preload", "/etc/ld.so.conf.d/", // dynamic linker — T1574.006
			"/etc/pam.d/", // PAM — T1556.003
			// Suffix entries (leading "*") catch every user's SSH key files,
			// including /root and /home/<user>, not just the exact /root path.
			"*/.ssh/authorized_keys", "*/.ssh/authorized_keys2", // SSH keys — T1098.004
			"/lib/security/", "/lib64/security/",
			"/usr/lib64/security/", "/usr/lib/x86_64-linux-gnu/security/",
			"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/",
			"/etc/sudoers", "/etc/sudoers.d/", // sudo privesc persistence — T1548.003

			// --- persistence paths (rule emits High) ---
			// Also written by package managers / admins, so High (not Critical). We
			// watch the ADMIN/attacker-primary locations under /etc and skip the
			// package-owned dirs (/usr/lib/systemd, /lib/udev, …) that would flood
			// on every package install with little added value.
			"/etc/systemd/system/", "/etc/systemd/user/", // systemd — T1543.002
			"/etc/crontab", "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/",
			"/etc/cron.weekly/", "/etc/cron.monthly/", "/var/spool/cron/", // cron — T1053.003
			"/etc/profile", "/etc/profile.d/", "/etc/bash.bashrc", "/etc/bashrc",
			"/etc/zsh/zshrc", "/etc/zsh/zshenv",
			"*/.bashrc", "*/.bash_profile", "*/.bash_login", "*/.profile",
			"*/.zshrc", "*/.zshenv", "*/.zprofile", // shell init — T1546.004
			"/etc/rc.local", "/etc/init.d/", // boot init scripts — T1037.004
			"/etc/udev/rules.d/",                                       // udev rules — T1546.017
			"/etc/modules-load.d/", "/etc/modprobe.d/", "/etc/modules", // kernel modules — T1547.006
			"/etc/xdg/autostart/", // XDG autostart — T1547.013
		},
		BPFLoaderAllowlist: []string{},
		BPFLoadFuncs:       []string{"security_bpf_prog_load", "bpf_check", "__sys_bpf"},
		// Genuinely write-path hooks only. security_file_permission fires on
		// read+write+exec, so it is mask-gated in the rule (MAY_WRITE=2); the
		// other two are inherently write/attribute-change paths. fd_install /
		// security_mmap_file (open/mmap of a file for read) were dropped — they
		// turned every read of a trust-path file into a Critical false positive.
		WriteFuncs: []string{
			"security_file_permission", "security_path_truncate",
			"security_inode_setattr",
		},

		// M3 response: SAFE defaults. No socket path (response is OPT-IN via
		// --response-socket / AGENT_RESPONSE_SOCKET), no token, response disabled
		// → DryRun stays true and nothing destructive can run. A non-empty default
		// here would make plain `agentd run` try to serve the socket and (without a
		// token) abort before detection ever starts.
		ResponseSocket:  "",
		ResponseEnabled: false,
		MgmtIfaces:      []string{"lo"},
		QuarantineDir:   "/var/lib/agentd/quarantine",
		ResponseMaxBody: 64 << 10,

		// Response brakes. The kill-switch defaults under /run/agentd so it lives on
		// tmpfs (clears on reboot, fast to touch) alongside the socket. The rate
		// limit defaults to 10 live actions per 60s — generous for a human operator,
		// but a hard cap on a runaway/hijacked mass-action.
		ResponseKillSwitch: "/run/agentd/response.disabled",
		ResponseRateMax:    10,
		ResponseRateWindow: 60 * time.Second,

		// Phase 4 auto-response: SAFE defaults. Mode off → the decision layer is a
		// no-op (no behaviour change). The auto rate budget is the auto path's OWN
		// (3 per 300s), independent of the manual budget above. The auto-only disarm
		// latch lives on tmpfs alongside the manual kill-switch but is a DISTINCT
		// file: tripping it never disarms manual response.
		AutoResponseMode:       "off",
		AutoResponseRateMax:    3,
		AutoResponseRateWindow: 300 * time.Second,
		AutoResponseDisabled:   "/run/agentd/autoresponse.disabled",
		AutoStaleTTL:           5 * time.Second,
		AutoNeverQuarantine:    nil,
		// Sensible private defaults: the operator's likely mgmt ranges. G7 already
		// rejects all RFC1918/CGNAT/link-local independently, so these are belt-and-
		// suspenders for any additionally-routed mgmt space.
		MgmtSubnets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	}
}

// Load overlays AGENT_* env vars on the defaults. getenv is injected for tests.
func Load(getenv func(string) string) Config {
	c := Defaults()
	if v := getenv("AGENT_TETRAGON_LOG"); v != "" {
		c.TetragonLog = v
	}
	if v := getenv("AGENT_COLLECTOR_URL"); v != "" {
		c.CollectorURL = v
	}
	if v := getenv("AGENT_COLLECTOR_AUTH"); v != "" {
		c.CollectorAuth = v
	}
	if v := getenv("AGENT_HOST"); v != "" {
		c.Host = v
	}
	if v := getenv("AGENT_BPF_ALLOWLIST"); v != "" {
		c.BPFLoaderAllowlist = splitList(v)
	}
	if v := getenv("AGENT_FLUSH_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.FlushInterval = time.Duration(n) * time.Second
		}
	}
	if v := getenv("AGENT_STATE_DIR"); v != "" {
		c.StateDir = v
	}
	// --- M3 response env ---
	if v := getenv("AGENT_RESPONSE_SOCKET"); v != "" {
		c.ResponseSocket = v
	}
	if v := getenv("AGENT_RESPONSE_TOKEN"); v != "" {
		c.ResponseToken = v
	}
	if v := getenv("AGENT_ENABLE_RESPONSE"); v != "" {
		c.ResponseEnabled = truthy(v)
	}
	if v := getenv("AGENT_MGMT_IFACES"); v != "" {
		// Always keep loopback in the keep-up set, even if the operator forgot it.
		c.MgmtIfaces = withLoopback(splitList(v))
	}
	if v := getenv("AGENT_QUARANTINE_DIR"); v != "" {
		c.QuarantineDir = v
	}
	// --- M3 response brakes ---
	if v := getenv("AGENT_RESPONSE_KILLSWITCH"); v != "" {
		c.ResponseKillSwitch = v
	}
	if v := getenv("AGENT_RESPONSE_RATE"); v != "" {
		// Form: "N/Ws" (e.g. "10/60s") or just "N" (window keeps its default).
		if max, win, ok := parseRate(v, c.ResponseRateWindow); ok {
			c.ResponseRateMax, c.ResponseRateWindow = max, win
		}
	}
	// --- Phase 4 auto-response env (all default-safe; unparseable → off/safe) ---
	if v := getenv("AGENT_AUTORESPONSE_MODE"); v != "" {
		// Normalize; an unrecognized value stays "off" (fail-safe). The bridge's
		// own parser is the authority on which modes are buildable.
		c.AutoResponseMode = strings.ToLower(strings.TrimSpace(v))
	}
	if v := getenv("AGENT_AUTORESPONSE_RATE"); v != "" {
		if max, win, ok := parseRate(v, c.AutoResponseRateWindow); ok {
			c.AutoResponseRateMax, c.AutoResponseRateWindow = max, win
		}
	}
	if v := getenv("AGENT_AUTORESPONSE_DISABLED"); v != "" {
		c.AutoResponseDisabled = v
	}
	if v := getenv("AGENT_AUTORESPONSE_STALE_TTL"); v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
			c.AutoStaleTTL = d
		}
	}
	if v := getenv("AGENT_AUTO_NEVER_QUARANTINE"); v != "" {
		c.AutoNeverQuarantine = splitList(v)
	}
	if v := getenv("AGENT_AUTO_PROTECTED_PATHS"); v != "" {
		c.AutoProtectedPaths = splitList(v)
	}
	if v := getenv("AGENT_MGMT_SUBNETS"); v != "" {
		c.MgmtSubnets = splitList(v)
	}
	return c
}

// parseRate parses an AGENT_RESPONSE_RATE value. Accepted forms:
//
//	"10"        → 10 per the default window
//	"10/60s"    → 10 per 60s (any time.ParseDuration window)
//	"10 per 5m" → 10 per 5m
//
// A value of "0" disables the limit. Returns ok=false (and the caller keeps its
// defaults) if the count is unparseable, so a typo can't silently remove the
// brake by setting an unbounded rate.
func parseRate(v string, defWindow time.Duration) (max int, window time.Duration, ok bool) {
	v = strings.TrimSpace(v)
	window = defWindow
	// Split on '/' or the word "per".
	var countStr, winStr string
	if i := strings.IndexByte(v, '/'); i >= 0 {
		countStr, winStr = v[:i], v[i+1:]
	} else if i := strings.Index(v, " per "); i >= 0 {
		countStr, winStr = v[:i], v[i+5:]
	} else {
		countStr = v
	}
	n, err := strconv.Atoi(strings.TrimSpace(countStr))
	if err != nil || n < 0 {
		return 0, defWindow, false
	}
	if winStr = strings.TrimSpace(winStr); winStr != "" {
		w, werr := time.ParseDuration(winStr)
		if werr != nil || w <= 0 {
			return 0, defWindow, false
		}
		window = w
	}
	return n, window, true
}

// truthy parses a permissive boolean env value: 1/true/yes/on (any case) → true.
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// withLoopback ensures "lo" is present so a custom mgmt-iface list can never
// accidentally make loopback isolable.
func withLoopback(ifaces []string) []string {
	for _, i := range ifaces {
		if strings.EqualFold(strings.TrimSpace(i), "lo") {
			return ifaces
		}
	}
	return append([]string{"lo"}, ifaces...)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
