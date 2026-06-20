package config

import (
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.TetragonLog == "" || d.FlushInterval <= 0 || d.BufferMax <= 0 {
		t.Errorf("defaults=%+v", d)
	}
	if len(d.StagingDirs) == 0 || len(d.SensitivePaths) == 0 || len(d.BPFLoadFuncs) == 0 || len(d.WriteFuncs) == 0 {
		t.Error("default rule inputs should be populated")
	}
}

func TestLoadEnvOverlay(t *testing.T) {
	env := map[string]string{
		"AGENT_TETRAGON_LOG":   "/var/log/t.json",
		"AGENT_COLLECTOR_URL":  "http://127.0.0.1:8787/ingest",
		"AGENT_COLLECTOR_AUTH": "Bearer xyz",
		"AGENT_HOST":           "lab-01",
		"AGENT_BPF_ALLOWLIST":  "/usr/bin/cilium-agent, /opt/tetragon/ ,,",
		"AGENT_FLUSH_SECONDS":  "5",
	}
	c := Load(func(k string) string { return env[k] })
	if c.TetragonLog != "/var/log/t.json" || c.CollectorURL != "http://127.0.0.1:8787/ingest" {
		t.Errorf("config=%+v", c)
	}
	if c.CollectorAuth != "Bearer xyz" || c.Host != "lab-01" {
		t.Errorf("config=%+v", c)
	}
	if len(c.BPFLoaderAllowlist) != 2 || c.BPFLoaderAllowlist[1] != "/opt/tetragon/" {
		t.Errorf("allowlist=%v", c.BPFLoaderAllowlist)
	}
	if c.FlushInterval != 5*time.Second {
		t.Errorf("flush=%v", c.FlushInterval)
	}
}

func TestLoadEmptyKeepsDefaults(t *testing.T) {
	c := Load(func(string) string { return "" })
	if c.TetragonLog != Defaults().TetragonLog || c.FlushInterval != Defaults().FlushInterval {
		t.Errorf("empty env should keep defaults: %+v", c)
	}
}
