package egress

import (
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

const allowlistJSON = `{
  "allow_loopback": true,
  "allow_private": false,
  "rules": [
    {"name": "tailscale", "cidr": "100.64.0.0/10"},
    {"name": "debian-mirror", "host": "deb.debian.org", "resolved_ips": ["151.101.0.204"], "proto": "tcp", "ports": [80, 443]},
    {"name": "https-anywhere", "proto": "tcp", "ports": [443]},
    {"name": "dns", "proto": "udp", "ports": [53]}
  ]
}`

func parseAL(t *testing.T) Allowlist {
	t.Helper()
	al, err := ParseAllowlist([]byte(allowlistJSON))
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	return al
}

func TestParseAllowlistBadCIDR(t *testing.T) {
	_, err := ParseAllowlist([]byte(`{"rules":[{"name":"x","cidr":"not-a-cidr"}]}`))
	if err == nil {
		t.Error("a malformed CIDR must be a hard error, not silently dropped")
	}
}

func TestParseAllowlistDefaultLoopback(t *testing.T) {
	al, err := ParseAllowlist([]byte(`{"rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !al.AllowLoopback {
		t.Error("loopback should default to allowed when unspecified")
	}
	al2, _ := ParseAllowlist([]byte(`{"allow_loopback":false,"rules":[]}`))
	if al2.AllowLoopback {
		t.Error("explicit allow_loopback:false must win")
	}
}

func TestEvaluateTable(t *testing.T) {
	al := parseAL(t)
	cases := []struct {
		name        string
		c           Conn
		wantAllowed bool
		wantRule    string
	}{
		{"tailscale-cidr", Conn{Proto: "tcp", RemoteAddr: mustAddr(t, "100.100.100.100"), RemotePort: 22, State: "ESTAB"}, true, "tailscale"},
		{"debian-resolved", Conn{Proto: "tcp", RemoteAddr: mustAddr(t, "151.101.0.204"), RemotePort: 443}, true, "debian-mirror"},
		{"https-anywhere", Conn{Proto: "tcp", RemoteAddr: mustAddr(t, "140.82.112.3"), RemotePort: 443}, true, "https-anywhere"},
		{"dns-udp", Conn{Proto: "udp", RemoteAddr: mustAddr(t, "1.1.1.1"), RemotePort: 53}, true, "dns"},
		{"loopback", Conn{Proto: "tcp", RemoteAddr: mustAddr(t, "127.0.0.1"), RemotePort: 9999}, true, ""},
		// Denials:
		{"evil-c2-high-port", Conn{Proto: "tcp", RemoteAddr: mustAddr(t, "23.254.164.123"), RemotePort: 4444}, false, ""},
		{"http-not-allowed-host", Conn{Proto: "tcp", RemoteAddr: mustAddr(t, "8.8.8.8"), RemotePort: 80}, false, ""},
		{"private-not-allowed", Conn{Proto: "tcp", RemoteAddr: mustAddr(t, "192.168.1.50"), RemotePort: 445}, false, ""},
		{"dns-over-tcp-denied", Conn{Proto: "tcp", RemoteAddr: mustAddr(t, "1.1.1.1"), RemotePort: 53}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := al.Evaluate(tc.c)
			if d.Allowed != tc.wantAllowed {
				t.Fatalf("allowed=%v want %v (reason=%q rule=%q)", d.Allowed, tc.wantAllowed, d.Reason, d.RuleHit)
			}
			if tc.wantAllowed && tc.wantRule != "" && d.RuleHit != tc.wantRule {
				t.Errorf("rule=%q want %q", d.RuleHit, tc.wantRule)
			}
		})
	}
}

func TestEvaluatePrivateToggle(t *testing.T) {
	al := parseAL(t)
	priv := Conn{Proto: "tcp", RemoteAddr: mustAddr(t, "10.0.0.5"), RemotePort: 8080}
	if al.Evaluate(priv).Allowed {
		t.Error("private remote must be denied when allow_private is false")
	}
	al.AllowPrivate = true
	if !al.Evaluate(priv).Allowed {
		t.Error("private remote must be allowed when allow_private is true")
	}
}

func TestEvaluate4In6MappedMatchesV4CIDR(t *testing.T) {
	al := parseAL(t)
	// A v4-mapped-v6 remote inside the Tailscale CGNAT range must still match.
	mapped := netip.AddrFrom16(netip.MustParseAddr("100.100.100.100").As16())
	c := Conn{Proto: "tcp", RemoteAddr: mapped, RemotePort: 22}
	if d := al.Evaluate(c); !d.Allowed || d.RuleHit != "tailscale" {
		t.Errorf("4-in-6 mapped addr should match v4 CIDR: %+v", d)
	}
}

func TestEvaluateNoRemoteIsAllowed(t *testing.T) {
	al := parseAL(t)
	if !al.Evaluate(Conn{Proto: "tcp", RemoteAddr: netip.IPv4Unspecified(), RemotePort: 0}).Allowed {
		t.Error("a socket with no remote peer is not egress and must be allowed")
	}
	if !al.Evaluate(Conn{Proto: "tcp"}).Allowed { // invalid (zero) addr
		t.Error("an invalid remote addr must be treated as not-egress")
	}
}

func TestEvaluateAll(t *testing.T) {
	al := parseAL(t)
	conns := []Conn{
		{Proto: "tcp", RemoteAddr: mustAddr(t, "140.82.112.3"), RemotePort: 443},
		{Proto: "tcp", RemoteAddr: mustAddr(t, "23.254.164.123"), RemotePort: 4444},
	}
	ds := al.EvaluateAll(conns)
	if len(ds) != 2 || !ds[0].Allowed || ds[1].Allowed {
		t.Errorf("decisions=%+v", ds)
	}
}
