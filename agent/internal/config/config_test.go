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
	if d.StateDir != "/var/lib/agentd" {
		t.Errorf("StateDir default should be /var/lib/agentd, got %q", d.StateDir)
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
		"AGENT_STATE_DIR":      "/srv/agentd-state",
	}
	c := Load(func(k string) string { return env[k] })
	if c.TetragonLog != "/var/log/t.json" || c.CollectorURL != "http://127.0.0.1:8787/ingest" {
		t.Errorf("config=%+v", c)
	}
	if c.StateDir != "/srv/agentd-state" {
		t.Errorf("StateDir override=%q", c.StateDir)
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

func TestResponseDefaultsAreSafe(t *testing.T) {
	d := Defaults()
	if d.ResponseEnabled {
		t.Error("ResponseEnabled must default to FALSE (dry-run stays on)")
	}
	if d.ResponseToken != "" {
		t.Error("ResponseToken should default empty (response fails closed)")
	}
	// Response is OPT-IN: a non-empty default socket makes plain `agentd run`
	// (detection) try to serve it and abort without a token — which is exactly
	// the bug that broke detection on a real host. The default MUST be empty.
	if d.ResponseSocket != "" {
		t.Errorf("ResponseSocket must default EMPTY (response opt-in), got %q", d.ResponseSocket)
	}
	if d.QuarantineDir == "" || d.ResponseMaxBody <= 0 {
		t.Errorf("response defaults=%+v", d)
	}
	if len(d.MgmtIfaces) == 0 || d.MgmtIfaces[0] != "lo" {
		t.Errorf("loopback should be a default mgmt iface: %v", d.MgmtIfaces)
	}
}

func TestLoadResponseEnv(t *testing.T) {
	env := map[string]string{
		"AGENT_RESPONSE_SOCKET": "/run/custom.sock",
		"AGENT_RESPONSE_TOKEN":  "resp-secret",
		"AGENT_ENABLE_RESPONSE": "1",
		"AGENT_MGMT_IFACES":     "tailscale0, eth0",
		"AGENT_QUARANTINE_DIR":  "/srv/quarantine",
	}
	c := Load(func(k string) string { return env[k] })
	if c.ResponseSocket != "/run/custom.sock" || c.ResponseToken != "resp-secret" {
		t.Errorf("response socket/token=%+v", c)
	}
	if !c.ResponseEnabled {
		t.Error("AGENT_ENABLE_RESPONSE=1 should enable response")
	}
	if c.QuarantineDir != "/srv/quarantine" {
		t.Errorf("quarantine dir=%q", c.QuarantineDir)
	}
	// loopback auto-added in front of the operator's list.
	if len(c.MgmtIfaces) != 3 || c.MgmtIfaces[0] != "lo" {
		t.Errorf("mgmt ifaces=%v (loopback should be prepended)", c.MgmtIfaces)
	}
}

func TestEnableResponseTruthiness(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		c := Load(func(k string) string {
			if k == "AGENT_ENABLE_RESPONSE" {
				return v
			}
			return ""
		})
		if !c.ResponseEnabled {
			t.Errorf("%q should enable response", v)
		}
	}
	for _, v := range []string{"0", "false", "no", "off", "", "nonsense"} {
		c := Load(func(k string) string {
			if k == "AGENT_ENABLE_RESPONSE" {
				return v
			}
			return ""
		})
		if c.ResponseEnabled {
			t.Errorf("%q should NOT enable response (must default safe)", v)
		}
	}
}

func TestResponseBrakeDefaults(t *testing.T) {
	d := Defaults()
	if d.ResponseKillSwitch == "" {
		t.Error("ResponseKillSwitch should have a non-empty default (the brake is on by default)")
	}
	if d.ResponseRateMax <= 0 {
		t.Errorf("ResponseRateMax should default to a positive cap, got %d", d.ResponseRateMax)
	}
	if d.ResponseRateWindow <= 0 {
		t.Errorf("ResponseRateWindow should default positive, got %v", d.ResponseRateWindow)
	}
}

func TestLoadResponseBrakeEnv(t *testing.T) {
	env := map[string]string{
		"AGENT_RESPONSE_KILLSWITCH": "/tmp/disarm",
		"AGENT_RESPONSE_RATE":       "5/30s",
	}
	c := Load(func(k string) string { return env[k] })
	if c.ResponseKillSwitch != "/tmp/disarm" {
		t.Errorf("kill-switch path=%q", c.ResponseKillSwitch)
	}
	if c.ResponseRateMax != 5 || c.ResponseRateWindow != 30*time.Second {
		t.Errorf("rate=%d per %v (want 5 per 30s)", c.ResponseRateMax, c.ResponseRateWindow)
	}
}

func TestParseRateForms(t *testing.T) {
	def := Defaults()
	cases := []struct {
		in        string
		wantMax   int
		wantWin   time.Duration
		wantOK    bool // whether the value should be applied (false ⇒ keep defaults)
		wantUnset bool // value absent ⇒ keep defaults
	}{
		{in: "10/60s", wantMax: 10, wantWin: 60 * time.Second, wantOK: true},
		{in: "3", wantMax: 3, wantWin: def.ResponseRateWindow, wantOK: true}, // count only, keep default window
		{in: "0", wantMax: 0, wantWin: def.ResponseRateWindow, wantOK: true}, // 0 disables the limit
		{in: "7 per 5m", wantMax: 7, wantWin: 5 * time.Minute, wantOK: true},
		{in: "garbage", wantUnset: true}, // unparseable ⇒ keep defaults (don't silently unbound)
		{in: "5/notaduration", wantUnset: true},
		{in: "-1/60s", wantUnset: true},
	}
	for _, c := range cases {
		cfg := Load(func(k string) string {
			if k == "AGENT_RESPONSE_RATE" {
				return c.in
			}
			return ""
		})
		if c.wantUnset {
			if cfg.ResponseRateMax != def.ResponseRateMax || cfg.ResponseRateWindow != def.ResponseRateWindow {
				t.Errorf("%q should keep defaults, got %d per %v", c.in, cfg.ResponseRateMax, cfg.ResponseRateWindow)
			}
			continue
		}
		if cfg.ResponseRateMax != c.wantMax || cfg.ResponseRateWindow != c.wantWin {
			t.Errorf("%q → %d per %v, want %d per %v", c.in, cfg.ResponseRateMax, cfg.ResponseRateWindow, c.wantMax, c.wantWin)
		}
	}
}

func TestMgmtIfacesAlwaysKeepsLoopback(t *testing.T) {
	c := Load(func(k string) string {
		if k == "AGENT_MGMT_IFACES" {
			return "eth0" // operator forgot loopback
		}
		return ""
	})
	found := false
	for _, i := range c.MgmtIfaces {
		if i == "lo" {
			found = true
		}
	}
	if !found {
		t.Errorf("loopback must always be kept up: %v", c.MgmtIfaces)
	}
}
