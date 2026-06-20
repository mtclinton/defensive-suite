package config

import "testing"

func TestDefaultsBindLoopback(t *testing.T) {
	d := Defaults()
	if d.Addr != "127.0.0.1:8787" {
		t.Errorf("default should bind loopback, got %q", d.Addr)
	}
	if d.Token != "" {
		t.Error("default token should be empty (ingest fails closed)")
	}
	if d.MaxBodyBytes <= 0 || d.RetentionDays <= 0 {
		t.Errorf("defaults=%+v", d)
	}
}

func TestLoadEnvOverlay(t *testing.T) {
	env := map[string]string{
		"COLLECTOR_ADDR":           "100.64.0.1:9000",
		"COLLECTOR_TOKEN":          "s3cret",
		"COLLECTOR_DATA_DIR":       "/var/lib/collector",
		"COLLECTOR_RETENTION_DAYS": "7",
		"COLLECTOR_MAX_REPORTS":    "100",
	}
	c := Load(func(k string) string { return env[k] })
	if c.Addr != "100.64.0.1:9000" || c.Token != "s3cret" || c.DataDir != "/var/lib/collector" {
		t.Errorf("env overlay: %+v", c)
	}
	if c.RetentionDays != 7 || c.MaxReports != 100 {
		t.Errorf("numeric env: retention=%d max=%d", c.RetentionDays, c.MaxReports)
	}
}

func TestLoadEmptyKeepsDefaults(t *testing.T) {
	c := Load(func(string) string { return "" })
	if c.Addr != Defaults().Addr || c.RetentionDays != Defaults().RetentionDays {
		t.Errorf("empty env should keep defaults: %+v", c)
	}
}

func TestResponseDefaultsAreSafe(t *testing.T) {
	d := Defaults()
	if d.AgentSocket != "" || d.ResponseToken != "" {
		t.Errorf("response should default disabled (both empty): %+v", d)
	}
}

func TestLoadResponseEnv(t *testing.T) {
	env := map[string]string{
		"COLLECTOR_AGENT_SOCKET":   "/run/agentd.sock",
		"COLLECTOR_RESPONSE_TOKEN": "resp-tok",
	}
	c := Load(func(k string) string { return env[k] })
	if c.AgentSocket != "/run/agentd.sock" || c.ResponseToken != "resp-tok" {
		t.Errorf("response env overlay: %+v", c)
	}
}

func TestLoadBadNumberKeepsDefault(t *testing.T) {
	c := Load(func(k string) string {
		if k == "COLLECTOR_RETENTION_DAYS" {
			return "not-a-number"
		}
		return ""
	})
	if c.RetentionDays != Defaults().RetentionDays {
		t.Errorf("bad number should keep default, got %d", c.RetentionDays)
	}
}
