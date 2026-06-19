// Package config holds instguard runtime configuration, loaded from built-in
// defaults, an optional JSON file, then environment overrides (env wins).
// Secrets and host/site specifics come from the environment so nothing sensitive
// is baked into source (see CLAUDE.md / THREAT_MODEL.md).
package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// DefaultOSVQueryURL is the OSV.dev single-query endpoint. It is overridable so
// tests can point it at an httptest server and air-gapped sites at a mirror.
const DefaultOSVQueryURL = "https://api.osv.dev/v1/query"

// Config is the full set of paths and toggles a run needs. Every filesystem
// location is overridable so the tool adapts across projects without code changes.
type Config struct {
	// WebhookURL receives the JSON report. Blank disables the webhook.
	WebhookURL string `json:"webhook_url"`
	// WebhookAuth is the Authorization header value; env-only, never serialized.
	WebhookAuth string `json:"-"`

	// ProjectDir is the npm project root scanned for package.json + lockfiles.
	ProjectDir string `json:"project_dir"`
	// OSVQueryURL is the OSV.dev query endpoint (overridable for mirrors/tests).
	OSVQueryURL string `json:"osv_query_url"`
	// CooldownDays flags any version published within this many days as too fresh
	// to trust (most malicious uploads earn a MAL- classification within ~3 days).
	CooldownDays int `json:"cooldown_days"`
	// NPMLogsDir is the directory `instguard audit` scans for postinstall runs.
	// Blank means "use $HOME/.npm/_logs".
	NPMLogsDir string `json:"npm_logs_dir"`

	// AURPaths are the AUR build files parsed for unexpected npm/bun invocations.
	// Globs are resolved relative to the project dir when not absolute.
	AURPaths []string `json:"aur_paths"`
	// OfflineOSV disables the OSV network query (air-gapped / CI without egress).
	OfflineOSV bool `json:"offline_osv"`
}

// Defaults returns a Config populated for a typical npm project in the current
// directory. Nonexistent files are simply skipped at scan time.
func Defaults() Config {
	return Config{
		ProjectDir:   ".",
		OSVQueryURL:  DefaultOSVQueryURL,
		CooldownDays: 3,
		AURPaths: []string{
			"PKGBUILD",
			"*.install",
			"*.hook",
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
	if v := getenv("INSTGUARD_WEBHOOK_URL"); v != "" {
		c.WebhookURL = v
	}
	if v := getenv("INSTGUARD_WEBHOOK_AUTH"); v != "" {
		c.WebhookAuth = v
	}
	if v := getenv("INSTGUARD_PROJECT_DIR"); v != "" {
		c.ProjectDir = v
	}
	if v := getenv("INSTGUARD_OSV_URL"); v != "" {
		c.OSVQueryURL = v
	}
	if v := getenv("INSTGUARD_COOLDOWN_DAYS"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			c.CooldownDays = n
		}
	}
	if v := getenv("INSTGUARD_NPM_LOGS_DIR"); v != "" {
		c.NPMLogsDir = v
	}
	if v := getenv("INSTGUARD_OFFLINE_OSV"); v != "" {
		c.OfflineOSV = parseBool(v)
	}
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
