package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsPopulated(t *testing.T) {
	d := Defaults()
	if d.ProjectDir == "" {
		t.Error("project dir empty")
	}
	if d.OSVQueryURL != DefaultOSVQueryURL {
		t.Errorf("osv url=%q", d.OSVQueryURL)
	}
	if d.CooldownDays != 3 {
		t.Errorf("cooldown=%d want 3 (DESIGN.md)", d.CooldownDays)
	}
	if len(d.AURPaths) == 0 {
		t.Error("aur paths empty")
	}
}

func TestApplyEnvPrecedence(t *testing.T) {
	c := Defaults()
	c.WebhookURL = "file-url"
	c.CooldownDays = 7
	env := map[string]string{
		"INSTGUARD_WEBHOOK_URL":   "env-url",
		"INSTGUARD_WEBHOOK_AUTH":  "secret",
		"INSTGUARD_PROJECT_DIR":   "/srv/app",
		"INSTGUARD_OSV_URL":       "http://mirror/v1/query",
		"INSTGUARD_COOLDOWN_DAYS": "5",
		"INSTGUARD_NPM_LOGS_DIR":  "/var/log/npm",
		"INSTGUARD_OFFLINE_OSV":   "true",
	}
	c.applyEnv(func(k string) string { return env[k] })
	if c.WebhookURL != "env-url" {
		t.Errorf("env should win: %q", c.WebhookURL)
	}
	if c.WebhookAuth != "secret" {
		t.Errorf("auth=%q", c.WebhookAuth)
	}
	if c.ProjectDir != "/srv/app" || c.OSVQueryURL != "http://mirror/v1/query" {
		t.Errorf("project=%q osv=%q", c.ProjectDir, c.OSVQueryURL)
	}
	if c.CooldownDays != 5 {
		t.Errorf("cooldown=%d want 5", c.CooldownDays)
	}
	if c.NPMLogsDir != "/var/log/npm" {
		t.Errorf("npm logs=%q", c.NPMLogsDir)
	}
	if !c.OfflineOSV {
		t.Error("offline osv should be true")
	}
}

func TestApplyEnvEmptyKeepsExisting(t *testing.T) {
	c := Defaults()
	c.WebhookURL = "file-url"
	c.CooldownDays = 9
	c.applyEnv(func(string) string { return "" })
	if c.WebhookURL != "file-url" {
		t.Errorf("empty env should keep existing value: %q", c.WebhookURL)
	}
	if c.CooldownDays != 9 {
		t.Errorf("empty env should keep cooldown: %d", c.CooldownDays)
	}
}

func TestApplyEnvBadIntIgnored(t *testing.T) {
	c := Defaults()
	c.applyEnv(func(k string) string {
		if k == "INSTGUARD_COOLDOWN_DAYS" {
			return "notanumber"
		}
		return ""
	})
	if c.CooldownDays != 3 {
		t.Errorf("bad int should be ignored, keeping default: %d", c.CooldownDays)
	}
}

func TestLoadFromFileKeepsDefaults(t *testing.T) {
	for _, k := range []string{"INSTGUARD_WEBHOOK_URL", "INSTGUARD_PROJECT_DIR", "INSTGUARD_OSV_URL", "INSTGUARD_COOLDOWN_DAYS"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"webhook_url":"http://x","project_dir":"/p","cooldown_days":10}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WebhookURL != "http://x" || c.ProjectDir != "/p" || c.CooldownDays != 10 {
		t.Errorf("loaded=%+v", c)
	}
	if c.OSVQueryURL != DefaultOSVQueryURL {
		t.Error("defaults should be preserved for unspecified fields")
	}
	if len(c.AURPaths) == 0 {
		t.Error("aur paths default should be preserved")
	}
}

func TestParseBool(t *testing.T) {
	for _, s := range []string{"1", "true", "TRUE", "yes", "on"} {
		if !parseBool(s) {
			t.Errorf("parseBool(%q)=false want true", s)
		}
	}
	for _, s := range []string{"0", "false", "no", "", "off", "x"} {
		if parseBool(s) {
			t.Errorf("parseBool(%q)=true want false", s)
		}
	}
}
