package respond

import "testing"

func testGuards() Guards {
	g := DefaultGuards()
	g.MgmtIfaces = []string{"lo", "tailscale0", "eth0"}
	g.SelfPID = 4242
	return g
}

func TestValidateKill(t *testing.T) {
	g := testGuards()
	cases := []struct {
		name   string
		target string
		ok     bool
	}{
		{"valid pid", "1234", true},
		{"pid 2", "2", true},
		{"pid 1 init", "1", false},
		{"pid 0", "0", false},
		{"negative", "-5", false},
		{"self pid", "4242", false},
		{"non numeric", "init", false},
		{"empty", "", false},
		{"whitespace numeric", "  77  ", true},
		{"float", "12.5", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := g.Validate(Request{Action: ActionKill, Target: c.target})
			if (err == nil) != c.ok {
				t.Fatalf("kill %q: ok=%v err=%v", c.target, c.ok, err)
			}
		})
	}
}

func TestValidateIsolate(t *testing.T) {
	g := testGuards()
	cases := []struct {
		name   string
		target string
		ok     bool
	}{
		{"non-mgmt iface", "wlan0", true},
		{"another non-mgmt", "docker0", true},
		{"mgmt lo", "lo", false},
		{"mgmt tailscale", "tailscale0", false},
		{"mgmt eth0", "eth0", false},
		{"mgmt case-insensitive", "ETH0", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := g.Validate(Request{Action: ActionIsolate, Target: c.target})
			if (err == nil) != c.ok {
				t.Fatalf("isolate %q: ok=%v err=%v", c.target, c.ok, err)
			}
		})
	}
}

func TestValidateQuarantine(t *testing.T) {
	g := testGuards()
	cases := []struct {
		name   string
		target string
		ok     bool
	}{
		{"tmp file", "/tmp/evil.bin", true},
		{"home file", "/home/max/Downloads/x", true},
		{"var tmp", "/var/tmp/payload", true},
		{"root dir", "/", false},
		{"proc", "/proc/1/maps", false},
		{"sys", "/sys/kernel/x", false},
		{"dev", "/dev/null", false},
		{"bin", "/bin/ls", false},
		{"sbin", "/sbin/init", false},
		{"usr", "/usr/bin/python", false},
		{"lib", "/lib/x.so", false},
		{"lib64", "/lib64/ld.so", false},
		{"libexec", "/libexec/x", false},
		{"boot", "/boot/vmlinuz", false},
		{"etc", "/etc/passwd", false},
		{"relative", "tmp/x", false},
		{"empty", "", false},
		{"traversal into etc", "/tmp/../etc/passwd", false},
		{"usr prefix lookalike not under usr", "/usrlocal/x", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := g.Validate(Request{Action: ActionQuarantine, Target: c.target})
			if (err == nil) != c.ok {
				t.Fatalf("quarantine %q: ok=%v err=%v", c.target, c.ok, err)
			}
		})
	}
}

func TestValidateRevokeKey(t *testing.T) {
	g := testGuards()
	fp := map[string]string{"fingerprint": "SHA256:abc"}
	cases := []struct {
		name   string
		target string
		args   map[string]string
		ok     bool
	}{
		{"valid", "/home/max/.ssh/authorized_keys", fp, true},
		{"authorized_keys2", "/root/.ssh/authorized_keys2", fp, true},
		{"missing fingerprint", "/home/max/.ssh/authorized_keys", nil, false},
		{"empty fingerprint", "/home/max/.ssh/authorized_keys", map[string]string{"fingerprint": "  "}, false},
		{"not authorized_keys", "/home/max/.ssh/id_rsa", fp, false},
		{"empty target", "", fp, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := g.Validate(Request{Action: ActionRevokeKey, Target: c.target, Args: c.args})
			if (err == nil) != c.ok {
				t.Fatalf("revoke-key %q args=%v: ok=%v err=%v", c.target, c.args, c.ok, err)
			}
		})
	}
}

func TestValidateBlockHash(t *testing.T) {
	g := testGuards()
	good := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	cases := []struct {
		name   string
		target string
		ok     bool
	}{
		{"valid lower", good, true},
		{"valid upper", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", true},
		{"too short", "abc123", false},
		{"63 chars", good[:63], false},
		{"65 chars", good + "a", false},
		{"non hex", "g" + good[1:], false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := g.Validate(Request{Action: ActionBlockHash, Target: c.target})
			if (err == nil) != c.ok {
				t.Fatalf("block-hash %q: ok=%v err=%v", c.target, c.ok, err)
			}
		})
	}
}

func TestValidateUnknownAction(t *testing.T) {
	g := testGuards()
	if err := g.Validate(Request{Action: "nuke", Target: "x"}); err == nil {
		t.Fatal("unknown action should be refused")
	}
}

func TestPathUnder(t *testing.T) {
	cases := []struct {
		clean, prefix string
		want          bool
	}{
		{"/usr/bin/x", "/usr", true},
		{"/usr", "/usr", true},
		{"/usrlocal/x", "/usr", false},
		{"/anything", "/", true},
		{"/etc/passwd", "/etc", true},
		{"/etcd/x", "/etc", false},
	}
	for _, c := range cases {
		if got := pathUnder(c.clean, c.prefix); got != c.want {
			t.Errorf("pathUnder(%q,%q)=%v want %v", c.clean, c.prefix, got, c.want)
		}
	}
}
