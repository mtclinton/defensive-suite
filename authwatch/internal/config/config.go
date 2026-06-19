// Package config holds authwatch runtime configuration, loaded from built-in
// defaults, an optional JSON file, then environment overrides (env wins).
// Secrets and host specifics come from the environment so nothing sensitive or
// site-specific is baked into source (see CLAUDE.md / THREAT_MODEL.md).
package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// Config is the full set of paths and toggles a run needs. Every filesystem
// location is overridable so the tool adapts across distros without code changes.
type Config struct {
	// WebhookURL receives the JSON report. Blank disables the webhook.
	WebhookURL string `json:"webhook_url"`
	// WebhookAuth is the Authorization header value; env-only, never serialized.
	WebhookAuth string `json:"-"`
	// BaselinePath is the off-host hash baseline — the trust anchor. It should
	// live on read-only/off-host media; if it is writable on the box it is worthless.
	BaselinePath string `json:"baseline_path"`
	// AllowlistPath lists attributable SSH key fingerprints/pubkeys, one per line.
	AllowlistPath string `json:"allowlist_path"`
	// AIDEConfig is passed to `aide --config` when the AIDE check is enabled.
	AIDEConfig string `json:"aide_config"`

	// SecurityDirs are the PAM module directories scanned for unowned *.so files.
	SecurityDirs []string `json:"security_dirs"`
	// AuthBinaries are the auth-critical binaries/libraries verified and baselined.
	AuthBinaries []string `json:"auth_binaries"`
	// SSHKeyGlobs locate authorized_keys files to audit.
	SSHKeyGlobs []string `json:"ssh_key_globs"`
	// ShellInit are shell init files scanned for LD_PRELOAD assignments.
	ShellInit []string `json:"shell_init"`
	// SystemdDirs are scanned for unit Environment= LD_PRELOAD directives.
	SystemdDirs []string `json:"systemd_dirs"`
	// XLockGlob matches X11 lock files (QLNX fake-lockfile detection).
	XLockGlob string `json:"xlock_glob"`
	// XServerUIDs are the UIDs a legitimate X server lock file may be owned by.
	XServerUIDs []int `json:"xserver_uids"`
}

// Defaults returns a Config populated for a typical Linux workstation. Paths
// span both RPM (/lib64, /usr/lib64) and Debian (multiarch) layouts; nonexistent
// entries are simply skipped at scan time.
func Defaults() Config {
	return Config{
		AIDEConfig: "/etc/aide.conf",
		SecurityDirs: []string{
			"/lib/security", "/lib64/security",
			"/usr/lib/security", "/usr/lib64/security",
			"/usr/lib/x86_64-linux-gnu/security",
			"/usr/lib/aarch64-linux-gnu/security",
		},
		AuthBinaries: []string{
			"/usr/sbin/sshd", "/usr/bin/sshd",
			"/usr/bin/ssh",
			"/usr/bin/sudo", "/usr/bin/su", "/usr/bin/login", "/bin/login",
			"/lib64/libc.so.6", "/lib/libc.so.6",
			"/usr/lib/x86_64-linux-gnu/libc.so.6",
			"/usr/lib/aarch64-linux-gnu/libc.so.6",
		},
		SSHKeyGlobs: []string{
			"/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2",
			"/home/*/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys2",
			"/etc/ssh/authorized_keys.d/*",
		},
		ShellInit: []string{
			"/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bashrc",
			"/etc/environment", "/etc/zsh/zshenv",
			"/root/.bashrc", "/root/.bash_profile", "/root/.profile", "/root/.zshrc",
			"/home/*/.bashrc", "/home/*/.bash_profile", "/home/*/.profile", "/home/*/.zshrc",
		},
		SystemdDirs: []string{
			"/etc/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system",
		},
		XLockGlob:   "/tmp/.X*-lock",
		XServerUIDs: []int{0},
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
	if v := getenv("AUTHWATCH_WEBHOOK_URL"); v != "" {
		c.WebhookURL = v
	}
	if v := getenv("AUTHWATCH_WEBHOOK_AUTH"); v != "" {
		c.WebhookAuth = v
	}
	if v := getenv("AUTHWATCH_BASELINE"); v != "" {
		c.BaselinePath = v
	}
	if v := getenv("AUTHWATCH_ALLOWLIST"); v != "" {
		c.AllowlistPath = v
	}
	if v := getenv("AUTHWATCH_AIDE_CONFIG"); v != "" {
		c.AIDEConfig = v
	}
	if v := getenv("AUTHWATCH_XSERVER_UIDS"); v != "" {
		if ids := parseIntList(v); len(ids) > 0 {
			c.XServerUIDs = ids
		}
	}
}

func parseIntList(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			out = append(out, n)
		}
	}
	return out
}
