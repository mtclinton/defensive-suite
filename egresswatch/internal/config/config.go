// Package config holds egresswatch runtime configuration, loaded from built-in
// defaults, an optional JSON file, then environment overrides (env wins).
// Secrets and host specifics come from the environment so nothing sensitive or
// site-specific is baked into source (see CLAUDE.md / THREAT_MODEL.md).
package config

import (
	"encoding/json"
	"os"
	"strings"
)

// Config is the full set of paths and toggles a run needs. Every filesystem
// location is overridable so the tool adapts across distros without code changes.
type Config struct {
	// WebhookURL receives the JSON report. Blank disables the webhook.
	WebhookURL string `json:"webhook_url"`
	// WebhookAuth is the Authorization header value; env-only, never serialized.
	WebhookAuth string `json:"-"`

	// ProcDir is the /proc root the triage scanner reads. Overridable so tests
	// (and offline forensics over a mounted /proc snapshot) can point elsewhere.
	ProcDir string `json:"proc_dir"`

	// AllowlistPath is the expected-egress allowlist (JSON: CIDRs, hostnames,
	// ports). Connections outside it are flagged. Blank => egress check reports
	// observed connections informationally but judges nothing.
	AllowlistPath string `json:"allowlist_path"`

	// ConnSource selects how observed outbound connections are gathered when no
	// explicit input file is given: "ss" (parse `ss -tunp`) or "proc" (parse
	// /proc/net/tcp{,6}+/proc/net/udp{,6}). Default "proc" needs no external tool.
	ConnSource string `json:"conn_source"`
}

// Defaults returns a Config populated for a typical Linux workstation.
func Defaults() Config {
	return Config{
		ProcDir:    "/proc",
		ConnSource: "proc",
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
	cfg.normalize()
	return cfg, nil
}

// applyEnv overlays environment overrides. The getenv function is injected so
// the precedence logic is unit-testable without mutating process state.
func (c *Config) applyEnv(getenv func(string) string) {
	if v := getenv("EGRESSWATCH_WEBHOOK_URL"); v != "" {
		c.WebhookURL = v
	}
	if v := getenv("EGRESSWATCH_WEBHOOK_AUTH"); v != "" {
		c.WebhookAuth = v
	}
	if v := getenv("EGRESSWATCH_PROC_DIR"); v != "" {
		c.ProcDir = v
	}
	if v := getenv("EGRESSWATCH_ALLOWLIST"); v != "" {
		c.AllowlistPath = v
	}
	if v := getenv("EGRESSWATCH_CONN_SOURCE"); v != "" {
		c.ConnSource = v
	}
}

// normalize fills in any field a JSON file may have zeroed and lowercases the
// enum-style ConnSource.
func (c *Config) normalize() {
	if c.ProcDir == "" {
		c.ProcDir = "/proc"
	}
	c.ConnSource = strings.ToLower(strings.TrimSpace(c.ConnSource))
	if c.ConnSource != "ss" {
		c.ConnSource = "proc"
	}
}
