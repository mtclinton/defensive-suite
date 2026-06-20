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
}

// Defaults returns a safe baseline for a single Linux workstation.
func Defaults() Config {
	host, _ := os.Hostname()
	return Config{
		TetragonLog:   "/var/log/tetragon/tetragon.log",
		Host:          host,
		FlushInterval: 10 * time.Second,
		BufferMax:     1000,
		StagingDirs:   []string{"/tmp/", "/dev/shm/", "/var/tmp/"},
		SensitivePaths: []string{
			"/etc/ld.so.preload",
			"/etc/pam.d/",
			"/root/.ssh/authorized_keys",
			"/lib/security/", "/lib64/security/",
			"/usr/lib64/security/", "/usr/lib/x86_64-linux-gnu/security/",
			"/etc/ssh/sshd_config",
		},
		BPFLoaderAllowlist: []string{},
		BPFLoadFuncs:       []string{"security_bpf_prog_load", "bpf_check", "__sys_bpf"},
		WriteFuncs: []string{
			"security_file_permission", "security_inode_setattr",
			"security_path_truncate", "fd_install", "security_mmap_file",
		},
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
	return c
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
