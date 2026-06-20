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
}

// Defaults returns a safe baseline for a single Linux workstation.
func Defaults() Config {
	host, _ := os.Hostname()
	return Config{
		TetragonLog:   "/var/log/tetragon/tetragon.log",
		Host:          host,
		FlushInterval: 10 * time.Second,
		BufferMax:     5000,
		StagingDirs:   []string{"/tmp/", "/dev/shm/", "/var/tmp/"},
		SensitivePaths: []string{
			"/etc/ld.so.preload",
			"/etc/pam.d/",
			// Suffix entries (leading "*") catch every user's SSH key files,
			// including /root and /home/<user>, not just the exact /root path.
			"*/.ssh/authorized_keys",
			"*/.ssh/authorized_keys2",
			"/lib/security/", "/lib64/security/",
			"/usr/lib64/security/", "/usr/lib/x86_64-linux-gnu/security/",
			"/etc/ssh/sshd_config",
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

		// M3 response: SAFE defaults. No socket path, no token, response disabled
		// → DryRun stays true and nothing destructive can run.
		ResponseSocket:  "/run/agentd.sock",
		ResponseEnabled: false,
		MgmtIfaces:      []string{"lo"},
		QuarantineDir:   "/var/lib/agentd/quarantine",
		ResponseMaxBody: 64 << 10,
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
	return c
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
