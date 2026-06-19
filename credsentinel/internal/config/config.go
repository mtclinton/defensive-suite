// Package config holds credsentinel runtime configuration, loaded from built-in
// defaults, an optional JSON file, then environment overrides (env wins).
// Secrets and host specifics come from the environment so nothing sensitive or
// site-specific is baked into source (see CLAUDE.md / THREAT_MODEL.md). In
// particular the webhook auth token and the Canarytoken DNS hostname are env-only.
package config

import (
	"encoding/json"
	"os"
	"strings"
)

// Config is the full set of paths and toggles a run needs.
type Config struct {
	// WebhookURL receives the JSON report. Blank disables the webhook.
	WebhookURL string `json:"webhook_url"`
	// WebhookAuth is the Authorization header value; env-only, never serialized.
	WebhookAuth string `json:"-"`

	// ScanRoots are directories (repos, home) the exposure scanner walks with
	// gitleaks/trufflehog and the built-in fallback. "~" expands to the home dir.
	ScanRoots []string `json:"scan_roots"`
	// ScanTargets toggles scanning the exact stealer target file list (.npmrc,
	// .aws/credentials, .kube/config, SSH keys, Vault tokens, …) under the home dir.
	ScanTargets bool `json:"scan_targets"`
	// HomeDir overrides the home directory the stealer targets resolve against.
	// Blank means the process's real home (os.UserHomeDir).
	HomeDir string `json:"home_dir"`

	// HoneytokenDir is where decoy credentials are planted and where the
	// deployment manifest (path + fingerprint per decoy) is recorded. It defaults
	// to the home dir so decoys sit exactly where a stealer expects them.
	HoneytokenDir string `json:"honeytoken_dir"`
	// ManifestPath records each decoy's path, fingerprint and stat baseline. The
	// watch command compares live stat against it to detect a trip.
	ManifestPath string `json:"manifest_path"`
	// CanaryHost is the DNS-token hostname seeded into the decoy `.env` so a
	// process that resolves/exfiltrates it trips a self-hosted Canarytoken. It is
	// env-only and never serialized — it is site-specific token data.
	CanaryHost string `json:"-"`

	// MaxFileBytes caps how much of any single file the built-in scanner reads,
	// bounding memory against a hostile/huge file (e.g. a symlink to /dev/zero).
	MaxFileBytes int64 `json:"max_file_bytes"`
}

// Defaults returns a Config populated for a typical developer workstation. The
// stealer-target scan is on by default; scan roots are empty so a plain run only
// touches the known credential files unless repos are configured. Honeytoken
// paths default under the home directory and are resolved at use time.
func Defaults() Config {
	return Config{
		ScanRoots:     []string{},
		ScanTargets:   true,
		HoneytokenDir: "~",
		ManifestPath:  "~/.config/credsentinel/honeytokens.json",
		MaxFileBytes:  4 << 20, // 4 MiB
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
	if v := getenv("CREDSENTINEL_WEBHOOK_URL"); v != "" {
		c.WebhookURL = v
	}
	if v := getenv("CREDSENTINEL_WEBHOOK_AUTH"); v != "" {
		c.WebhookAuth = v
	}
	if v := getenv("CREDSENTINEL_SCAN_ROOTS"); v != "" {
		if roots := splitList(v); len(roots) > 0 {
			c.ScanRoots = roots
		}
	}
	if v := getenv("CREDSENTINEL_HOME"); v != "" {
		c.HomeDir = v
	}
	if v := getenv("CREDSENTINEL_HONEYTOKEN_DIR"); v != "" {
		c.HoneytokenDir = v
	}
	if v := getenv("CREDSENTINEL_MANIFEST"); v != "" {
		c.ManifestPath = v
	}
	if v := getenv("CREDSENTINEL_CANARY_HOST"); v != "" {
		c.CanaryHost = v
	}
}

// Home returns the home directory the targets/honeytokens resolve against:
// the configured HomeDir if set, otherwise the process's real home.
func (c Config) Home() string {
	if c.HomeDir != "" {
		return c.HomeDir
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// ExpandHome replaces a leading "~" in p with the resolved home directory.
func (c Config) ExpandHome(p string) string {
	return expandHome(p, c.Home())
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return home + p[1:]
	}
	return p
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
