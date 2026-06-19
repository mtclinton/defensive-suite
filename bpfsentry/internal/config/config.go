// Package config holds bpfsentry runtime configuration, loaded from built-in
// defaults, an optional JSON file, then environment overrides (env wins).
// Secrets and host specifics come from the environment so nothing sensitive or
// site-specific is baked into source (see CLAUDE.md / THREAT_MODEL.md).
package config

import (
	"encoding/json"
	"os"
	"strings"
)

// Config is the full set of paths and toggles a run needs. Every location is
// overridable so the tool adapts across distros and deployments without code
// changes.
type Config struct {
	// WebhookURL receives the JSON report. Blank disables the webhook.
	WebhookURL string `json:"webhook_url"`
	// WebhookAuth is the Authorization header value; env-only, never serialized.
	WebhookAuth string `json:"-"`

	// BaselinePath is the early-boot allowlist — the trust anchor. It should
	// live on read-only/off-host media; if it is writable on the box a rootkit
	// rewrites it and the diff is worthless.
	BaselinePath string `json:"baseline_path"`

	// BPFToolPath is the bpftool executable used for the portable enumeration
	// path. A bare name is resolved on PATH; an absolute path pins the binary.
	BPFToolPath string `json:"bpftool_path"`

	// AllowedLoaders are the program *names* a legitimate agent loads (Cilium,
	// your tracer, your EDR). A named program in the baseline that matches one of
	// these is trusted; one that does not is the highest-signal finding.
	AllowedLoaders []string `json:"allowed_loaders"`

	// SuspiciousHelpers are the BPF helpers whose presence in a program's
	// metadata is treated as high-signal (write-to-user-memory, override-return,
	// send-signal). Overridable so a site can add its own.
	SuspiciousHelpers []string `json:"suspicious_helpers"`
}

// Defaults returns a Config populated for a typical Linux workstation.
func Defaults() Config {
	return Config{
		BPFToolPath: "bpftool",
		// The legitimate loaders on a hardened workstation: the kernel's own
		// programs, a Cilium/Tetragon agent, the suite's tracer. A site tunes
		// this to the named programs its real agents load.
		AllowedLoaders: []string{},
		SuspiciousHelpers: []string{
			"bpf_override_return",
			"bpf_probe_write_user",
			"bpf_send_signal",
			"bpf_send_signal_thread",
		},
	}
}

// Load returns Defaults overlaid with an optional JSON file and then env vars.
// A blank path skips the file. Env overrides always win.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, err
		}
	}
	cfg.applyEnv(os.Getenv)
	return cfg, nil
}

// applyEnv overlays environment overrides. The getenv function is injected so
// the precedence logic is unit-testable without mutating process state.
func (c *Config) applyEnv(getenv func(string) string) {
	if v := getenv("BPFSENTRY_WEBHOOK_URL"); v != "" {
		c.WebhookURL = v
	}
	if v := getenv("BPFSENTRY_WEBHOOK_AUTH"); v != "" {
		c.WebhookAuth = v
	}
	if v := getenv("BPFSENTRY_BASELINE"); v != "" {
		c.BaselinePath = v
	}
	if v := getenv("BPFSENTRY_BPFTOOL"); v != "" {
		c.BPFToolPath = v
	}
	if v := getenv("BPFSENTRY_ALLOWED_LOADERS"); v != "" {
		if names := parseList(v); len(names) > 0 {
			c.AllowedLoaders = names
		}
	}
}

func parseList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
