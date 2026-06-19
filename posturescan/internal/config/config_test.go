package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsPopulated(t *testing.T) {
	d := Defaults()
	if d.ProcSysRoot == "" || d.LockdownPath == "" {
		t.Error("proc sys root / lockdown path should be set")
	}
	if len(d.SystemdDirs) == 0 {
		t.Error("systemd dirs empty")
	}
	if len(d.LegitBPFTools) == 0 {
		t.Error("legit bpf tools empty")
	}
	if d.SysctlDropInPath == "" {
		t.Error("dropin path empty")
	}
}

func TestApplyEnvPrecedence(t *testing.T) {
	c := Defaults()
	c.WebhookURL = "file-url"
	c.ProcSysRoot = "/file/proc"
	env := map[string]string{
		"POSTURESCAN_WEBHOOK_URL":     "env-url",
		"POSTURESCAN_WEBHOOK_AUTH":    "secret",
		"POSTURESCAN_PROC_SYS_ROOT":   "/env/proc",
		"POSTURESCAN_LOCKDOWN_PATH":   "/env/lockdown",
		"POSTURESCAN_PROFILE":         "/env/profile",
		"POSTURESCAN_CONTAINER_SPECS": "/a.json, /b.json ,",
	}
	c.applyEnv(func(k string) string { return env[k] })
	if c.WebhookURL != "env-url" {
		t.Errorf("env should win: %q", c.WebhookURL)
	}
	if c.WebhookAuth != "secret" {
		t.Errorf("auth=%q", c.WebhookAuth)
	}
	if c.ProcSysRoot != "/env/proc" || c.LockdownPath != "/env/lockdown" || c.ProfilePath != "/env/profile" {
		t.Errorf("paths=%+v", c)
	}
	if len(c.ContainerSpecs) != 2 || c.ContainerSpecs[1] != "/b.json" {
		t.Errorf("specs=%v", c.ContainerSpecs)
	}
}

func TestApplyEnvEmptyKeepsExisting(t *testing.T) {
	c := Defaults()
	c.WebhookURL = "file-url"
	c.applyEnv(func(string) string { return "" })
	if c.WebhookURL != "file-url" {
		t.Errorf("empty env should keep existing value: %q", c.WebhookURL)
	}
}

func TestLoadFromFileKeepsDefaults(t *testing.T) {
	for _, k := range []string{"POSTURESCAN_WEBHOOK_URL", "POSTURESCAN_PROC_SYS_ROOT", "POSTURESCAN_PROFILE"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"webhook_url":"http://x","proc_sys_root":"/p"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WebhookURL != "http://x" || c.ProcSysRoot != "/p" {
		t.Errorf("loaded=%+v", c)
	}
	if len(c.SystemdDirs) == 0 || len(c.LegitBPFTools) == 0 {
		t.Error("defaults should be preserved for unspecified fields")
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" /a , , /b ,/c ")
	if len(got) != 3 || got[0] != "/a" || got[2] != "/c" {
		t.Errorf("splitList=%v", got)
	}
}
