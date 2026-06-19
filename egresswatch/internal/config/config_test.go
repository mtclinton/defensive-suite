package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsPopulated(t *testing.T) {
	d := Defaults()
	if d.ProcDir != "/proc" {
		t.Errorf("proc_dir=%q", d.ProcDir)
	}
	if d.ConnSource != "proc" {
		t.Errorf("conn_source=%q", d.ConnSource)
	}
}

func TestApplyEnvPrecedence(t *testing.T) {
	c := Defaults()
	c.WebhookURL = "file-url"
	env := map[string]string{
		"EGRESSWATCH_WEBHOOK_URL":  "env-url",
		"EGRESSWATCH_WEBHOOK_AUTH": "secret",
		"EGRESSWATCH_PROC_DIR":     "/snap/proc",
		"EGRESSWATCH_ALLOWLIST":    "/a.json",
		"EGRESSWATCH_CONN_SOURCE":  "ss",
	}
	c.applyEnv(func(k string) string { return env[k] })
	if c.WebhookURL != "env-url" {
		t.Errorf("env should win: %q", c.WebhookURL)
	}
	if c.WebhookAuth != "secret" {
		t.Errorf("auth=%q", c.WebhookAuth)
	}
	if c.ProcDir != "/snap/proc" || c.AllowlistPath != "/a.json" || c.ConnSource != "ss" {
		t.Errorf("proc=%q allow=%q src=%q", c.ProcDir, c.AllowlistPath, c.ConnSource)
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

func TestNormalizeFillsAndClampsEnum(t *testing.T) {
	c := Config{ProcDir: "", ConnSource: "GARBAGE"}
	c.normalize()
	if c.ProcDir != "/proc" {
		t.Errorf("empty proc_dir should default: %q", c.ProcDir)
	}
	if c.ConnSource != "proc" {
		t.Errorf("unknown conn_source should clamp to proc: %q", c.ConnSource)
	}
	c2 := Config{ConnSource: "SS"}
	c2.normalize()
	if c2.ConnSource != "ss" {
		t.Errorf("ss should be accepted/lowercased: %q", c2.ConnSource)
	}
}

func TestLoadFromFileKeepsDefaults(t *testing.T) {
	for _, k := range []string{"EGRESSWATCH_WEBHOOK_URL", "EGRESSWATCH_PROC_DIR", "EGRESSWATCH_ALLOWLIST", "EGRESSWATCH_CONN_SOURCE"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"webhook_url":"http://x","allowlist_path":"/etc/egress.json"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WebhookURL != "http://x" || c.AllowlistPath != "/etc/egress.json" {
		t.Errorf("loaded=%+v", c)
	}
	if c.ProcDir != "/proc" || c.ConnSource != "proc" {
		t.Error("defaults should be preserved for unspecified fields")
	}
}

func TestLoadMissingFileErrors(t *testing.T) {
	if _, err := Load("/no/such/config/file.json"); err == nil {
		t.Error("missing config file should error")
	}
}
