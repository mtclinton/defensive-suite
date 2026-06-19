// Package config holds posturescan runtime configuration, loaded from built-in
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

	// ProcSysRoot is the /proc/sys-style directory the sysctl reader walks. When
	// a key is absent there, the reader falls back to parsing `sysctl -a` output.
	// Pointed at a fixture dir in tests so reads do not depend on the host.
	ProcSysRoot string `json:"proc_sys_root"`
	// LockdownPath is the kernel lockdown state file. Its content looks like
	// "none [integrity] confidentiality" with the active mode in brackets.
	LockdownPath string `json:"lockdown_path"`
	// ProfilePath is the target sysctl profile (KEY=VALUE lines). Blank uses the
	// built-in goal profile (ptrace_scope=2, unprivileged_bpf_disabled=2, ...).
	ProfilePath string `json:"profile_path"`

	// SystemdDirs are scanned for unit files granting CAP_SYS_ADMIN / CAP_BPF.
	SystemdDirs []string `json:"systemd_dirs"`
	// ContainerSpecs are OCI config.json / `podman inspect` JSON files audited
	// for dangerous capabilities and scored for Podman posture.
	ContainerSpecs []string `json:"container_specs"`
	// LegitBPFTools are unit/container names allowed to hold CAP_BPF /
	// CAP_SYS_ADMIN (a real eBPF observability tool needs them). Matched as a
	// substring against the unit filename or container name.
	LegitBPFTools []string `json:"legit_bpf_tools"`

	// SysctlDropInPath is where `remediate` says the drop-in *would* be written.
	// posturescan only ever prints it; it never writes to /etc.
	SysctlDropInPath string `json:"sysctl_dropin_path"`

	// OscapDatastream is the SCAP datastream XML to evaluate (e.g. the
	// scap-security-guide ssg-*-ds.xml). Blank skips the oscap wrapper.
	OscapDatastream string `json:"oscap_datastream"`
	// OscapProfile is the XCCDF profile id (e.g. xccdf_org.ssgproject...cis).
	OscapProfile string `json:"oscap_profile"`
}

// Defaults returns a Config populated for a typical Linux workstation.
func Defaults() Config {
	return Config{
		ProcSysRoot:  "/proc/sys",
		LockdownPath: "/sys/kernel/security/lockdown",
		SystemdDirs: []string{
			"/etc/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system",
		},
		// No container specs by default — they are workload-specific and supplied
		// explicitly (a path or `--spec`). An empty list degrades to a skip finding.
		ContainerSpecs: nil,
		LegitBPFTools: []string{
			// Known-good eBPF observability/security tooling that legitimately
			// needs CAP_BPF (and often CAP_SYS_ADMIN on older kernels).
			"tetragon", "cilium", "pixie", "parca", "bpftrace",
			"falco", "node-exporter", "bpfsentry", "egresswatch",
		},
		SysctlDropInPath: "/etc/sysctl.d/99-posturescan.conf",
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
	if v := getenv("POSTURESCAN_WEBHOOK_URL"); v != "" {
		c.WebhookURL = v
	}
	if v := getenv("POSTURESCAN_WEBHOOK_AUTH"); v != "" {
		c.WebhookAuth = v
	}
	if v := getenv("POSTURESCAN_PROC_SYS_ROOT"); v != "" {
		c.ProcSysRoot = v
	}
	if v := getenv("POSTURESCAN_LOCKDOWN_PATH"); v != "" {
		c.LockdownPath = v
	}
	if v := getenv("POSTURESCAN_PROFILE"); v != "" {
		c.ProfilePath = v
	}
	if v := getenv("POSTURESCAN_CONTAINER_SPECS"); v != "" {
		if specs := splitList(v); len(specs) > 0 {
			c.ContainerSpecs = specs
		}
	}
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
