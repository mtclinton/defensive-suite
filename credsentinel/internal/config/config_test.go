package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsPopulated(t *testing.T) {
	d := Defaults()
	if !d.ScanTargets {
		t.Error("scan_targets should default on")
	}
	if d.HoneytokenDir == "" || d.ManifestPath == "" {
		t.Error("honeytoken paths should be populated")
	}
	if d.MaxFileBytes <= 0 {
		t.Error("max file bytes should be positive")
	}
}

func TestApplyEnvPrecedence(t *testing.T) {
	c := Defaults()
	c.WebhookURL = "file-url"
	env := map[string]string{
		"CREDSENTINEL_WEBHOOK_URL":    "env-url",
		"CREDSENTINEL_WEBHOOK_AUTH":   "secret",
		"CREDSENTINEL_SCAN_ROOTS":     "/repo/a, /repo/b ,~",
		"CREDSENTINEL_HOME":           "/home/dev",
		"CREDSENTINEL_HONEYTOKEN_DIR": "/tmp/decoys",
		"CREDSENTINEL_MANIFEST":       "/tmp/m.json",
		"CREDSENTINEL_CANARY_HOST":    "abc123.canary.internal",
	}
	c.applyEnv(func(k string) string { return env[k] })
	if c.WebhookURL != "env-url" {
		t.Errorf("env should win: %q", c.WebhookURL)
	}
	if c.WebhookAuth != "secret" {
		t.Errorf("auth=%q", c.WebhookAuth)
	}
	if len(c.ScanRoots) != 3 || c.ScanRoots[1] != "/repo/b" {
		t.Errorf("roots=%v", c.ScanRoots)
	}
	if c.HomeDir != "/home/dev" {
		t.Errorf("home=%q", c.HomeDir)
	}
	if c.HoneytokenDir != "/tmp/decoys" || c.ManifestPath != "/tmp/m.json" {
		t.Errorf("honeytoken dir=%q manifest=%q", c.HoneytokenDir, c.ManifestPath)
	}
	if c.CanaryHost != "abc123.canary.internal" {
		t.Errorf("canary host=%q", c.CanaryHost)
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

func TestSecretsNotSerialized(t *testing.T) {
	c := Defaults()
	c.WebhookAuth = "Bearer top-secret"
	c.CanaryHost = "token.internal"
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "top-secret") {
		t.Error("webhook auth must never be serialized")
	}
	if strings.Contains(s, "token.internal") {
		t.Error("canary host (token data) must never be serialized")
	}
}

func TestLoadFromFileKeepsDefaults(t *testing.T) {
	for _, k := range []string{"CREDSENTINEL_WEBHOOK_URL", "CREDSENTINEL_SCAN_ROOTS", "CREDSENTINEL_HONEYTOKEN_DIR"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"webhook_url":"http://x","scan_roots":["/srv/repo"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WebhookURL != "http://x" || len(c.ScanRoots) != 1 || c.ScanRoots[0] != "/srv/repo" {
		t.Errorf("loaded=%+v", c)
	}
	if !c.ScanTargets || c.ManifestPath == "" {
		t.Error("defaults should be preserved for unspecified fields")
	}
}

func TestExpandHome(t *testing.T) {
	c := Config{HomeDir: "/home/dev"}
	if got := c.ExpandHome("~"); got != "/home/dev" {
		t.Errorf("~ -> %q", got)
	}
	if got := c.ExpandHome("~/.aws/credentials.bak"); got != "/home/dev/.aws/credentials.bak" {
		t.Errorf("~/path -> %q", got)
	}
	if got := c.ExpandHome("/abs/path"); got != "/abs/path" {
		t.Errorf("abs unchanged -> %q", got)
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" /a, /b ,, /c ")
	if len(got) != 3 || got[0] != "/a" || got[2] != "/c" {
		t.Errorf("splitList=%v", got)
	}
}
