package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsPopulated(t *testing.T) {
	d := Defaults()
	if d.BPFToolPath == "" {
		t.Error("bpftool path empty")
	}
	if len(d.SuspiciousHelpers) == 0 {
		t.Error("suspicious helpers empty")
	}
	// The three helpers the design names by hand must be present.
	want := map[string]bool{
		"bpf_override_return":  false,
		"bpf_probe_write_user": false,
		"bpf_send_signal":      false,
	}
	for _, h := range d.SuspiciousHelpers {
		if _, ok := want[h]; ok {
			want[h] = true
		}
	}
	for h, seen := range want {
		if !seen {
			t.Errorf("default suspicious helpers missing %q", h)
		}
	}
}

func TestApplyEnvPrecedence(t *testing.T) {
	c := Defaults()
	c.WebhookURL = "file-url"
	env := map[string]string{
		"BPFSENTRY_WEBHOOK_URL":     "env-url",
		"BPFSENTRY_WEBHOOK_AUTH":    "secret",
		"BPFSENTRY_BASELINE":        "/b",
		"BPFSENTRY_BPFTOOL":         "/usr/sbin/bpftool",
		"BPFSENTRY_ALLOWED_LOADERS": "cil_from_netdev, tetragon ,my_edr",
	}
	c.applyEnv(func(k string) string { return env[k] })
	if c.WebhookURL != "env-url" {
		t.Errorf("env should win: %q", c.WebhookURL)
	}
	if c.WebhookAuth != "secret" {
		t.Errorf("auth=%q", c.WebhookAuth)
	}
	if c.BaselinePath != "/b" {
		t.Errorf("baseline=%q", c.BaselinePath)
	}
	if c.BPFToolPath != "/usr/sbin/bpftool" {
		t.Errorf("bpftool=%q", c.BPFToolPath)
	}
	if len(c.AllowedLoaders) != 3 || c.AllowedLoaders[1] != "tetragon" {
		t.Errorf("loaders=%v", c.AllowedLoaders)
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
	for _, k := range []string{"BPFSENTRY_WEBHOOK_URL", "BPFSENTRY_BASELINE", "BPFSENTRY_BPFTOOL", "BPFSENTRY_ALLOWED_LOADERS"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"webhook_url":"http://x","baseline_path":"/b","allowed_loaders":["cil_from_netdev"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WebhookURL != "http://x" || c.BaselinePath != "/b" {
		t.Errorf("loaded=%+v", c)
	}
	if len(c.AllowedLoaders) != 1 || c.AllowedLoaders[0] != "cil_from_netdev" {
		t.Errorf("loaders=%v", c.AllowedLoaders)
	}
	if c.BPFToolPath != "bpftool" {
		t.Error("default bpftool path should be preserved for unspecified field")
	}
	if len(c.SuspiciousHelpers) == 0 {
		t.Error("defaults should be preserved for unspecified fields")
	}
}

func TestParseList(t *testing.T) {
	got := parseList(" a, b ,, , c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("parseList=%v", got)
	}
}
