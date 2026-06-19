package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsPopulated(t *testing.T) {
	d := Defaults()
	if len(d.SecurityDirs) == 0 || len(d.AuthBinaries) == 0 || len(d.SSHKeyGlobs) == 0 {
		t.Error("defaults should be populated")
	}
	if d.XLockGlob == "" {
		t.Error("xlock glob empty")
	}
	if len(d.XServerUIDs) == 0 {
		t.Error("xserver uids empty")
	}
}

func TestApplyEnvPrecedence(t *testing.T) {
	c := Defaults()
	c.WebhookURL = "file-url"
	env := map[string]string{
		"AUTHWATCH_WEBHOOK_URL":  "env-url",
		"AUTHWATCH_WEBHOOK_AUTH": "secret",
		"AUTHWATCH_BASELINE":     "/b",
		"AUTHWATCH_ALLOWLIST":    "/a",
		"AUTHWATCH_XSERVER_UIDS": "0, 1000 ,1001",
	}
	c.applyEnv(func(k string) string { return env[k] })
	if c.WebhookURL != "env-url" {
		t.Errorf("env should win: %q", c.WebhookURL)
	}
	if c.WebhookAuth != "secret" {
		t.Errorf("auth=%q", c.WebhookAuth)
	}
	if c.BaselinePath != "/b" || c.AllowlistPath != "/a" {
		t.Errorf("baseline=%q allowlist=%q", c.BaselinePath, c.AllowlistPath)
	}
	if len(c.XServerUIDs) != 3 || c.XServerUIDs[1] != 1000 {
		t.Errorf("uids=%v", c.XServerUIDs)
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
	for _, k := range []string{"AUTHWATCH_WEBHOOK_URL", "AUTHWATCH_BASELINE", "AUTHWATCH_ALLOWLIST"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"webhook_url":"http://x","baseline_path":"/b"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WebhookURL != "http://x" || c.BaselinePath != "/b" {
		t.Errorf("loaded=%+v", c)
	}
	if len(c.SecurityDirs) == 0 {
		t.Error("defaults should be preserved for unspecified fields")
	}
}

func TestParseIntList(t *testing.T) {
	got := parseIntList(" 0, 12 ,, x, 1000 ")
	if len(got) != 3 || got[0] != 0 || got[1] != 12 || got[2] != 1000 {
		t.Errorf("parseIntList=%v", got)
	}
}
