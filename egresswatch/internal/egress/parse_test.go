package egress

import (
	"testing"
)

const ssFixture = `Netid State  Recv-Q Send-Q Local Address:Port   Peer Address:Port  Process
tcp   ESTAB  0      0      192.168.1.5:54321    140.82.112.3:443   users:(("curl",pid=42,fd=3))
tcp   LISTEN 0      128    0.0.0.0:22           0.0.0.0:*
tcp   ESTAB  0      0      [2001:db8::5]:50000  [2606:4700::1111]:443 users:(("node",pid=99,fd=7))
udp   UNCONN 0      0      192.168.1.5:43210    1.1.1.1:53         users:(("systemd-resolve",pid=7,fd=12))
tcp   TIME-WAIT 0   0      192.168.1.5:55555    93.184.216.34:80
`

func TestParseSS(t *testing.T) {
	conns := ParseSS(ssFixture)
	// ESTAB tcp (v4), ESTAB tcp (v6), UNCONN udp == 3; LISTEN and TIME-WAIT dropped.
	if len(conns) != 3 {
		t.Fatalf("want 3 conns, got %d: %+v", len(conns), conns)
	}
	c0 := conns[0]
	if c0.Proto != "tcp" || c0.RemoteAddr.String() != "140.82.112.3" || c0.RemotePort != 443 {
		t.Errorf("c0=%+v", c0)
	}
	if c0.Process != "curl/42" {
		t.Errorf("process=%q want curl/42", c0.Process)
	}
	if conns[1].RemoteAddr.String() != "2606:4700::1111" || conns[1].RemotePort != 443 {
		t.Errorf("v6 conn=%+v", conns[1])
	}
	if conns[2].Proto != "udp" || conns[2].RemotePort != 53 || conns[2].Process != "systemd-resolve/7" {
		t.Errorf("udp conn=%+v", conns[2])
	}
}

func TestParseSSEmpty(t *testing.T) {
	if c := ParseSS(""); len(c) != 0 {
		t.Errorf("empty input should yield no conns: %+v", c)
	}
	if c := ParseSS("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"); len(c) != 0 {
		t.Errorf("header-only should yield no conns: %+v", c)
	}
}

func TestSplitAddrPort(t *testing.T) {
	cases := []struct {
		tok      string
		wantAddr string
		wantPort uint16
		wantOK   bool
	}{
		{"140.82.112.3:443", "140.82.112.3", 443, true},
		{"[2606:4700::1111]:443", "2606:4700::1111", 443, true},
		{"fe80::1%eth0:22", "fe80::1", 22, true},
		{"0.0.0.0:*", "0.0.0.0", 0, true},
		{"*:*", "0.0.0.0", 0, true},
		{"garbage", "", 0, false},
	}
	for _, tc := range cases {
		a, p, ok := splitAddrPort(tc.tok)
		if ok != tc.wantOK {
			t.Errorf("%q ok=%v want %v", tc.tok, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if a.String() != tc.wantAddr || p != tc.wantPort {
			t.Errorf("%q -> %s:%d want %s:%d", tc.tok, a, p, tc.wantAddr, tc.wantPort)
		}
	}
}

// /proc/net/tcp fixture. Address words are little-endian hex.
//
//	local 0501A8C0 = 192.168.1.5 ; port 0xD431 = 54321
//	rem   0370528C = 140.82.112.3 ; port 0x01BB = 443 ; st 01 = ESTAB
//
// A second row is a LISTEN (st 0A) with a zero remote -> dropped.
const procTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0501A8C0:D431 0370528C:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 ffff 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 ffff 100 0 0 10 0
`

func TestParseProcNetTCP(t *testing.T) {
	conns := ParseProcNet(procTCPFixture, "tcp", false)
	if len(conns) != 1 {
		t.Fatalf("want 1 established conn (listener dropped), got %d: %+v", len(conns), conns)
	}
	c := conns[0]
	if c.LocalAddr.String() != "192.168.1.5" || c.LocalPort != 54321 {
		t.Errorf("local=%s:%d", c.LocalAddr, c.LocalPort)
	}
	if c.RemoteAddr.String() != "140.82.112.3" || c.RemotePort != 443 {
		t.Errorf("remote=%s:%d", c.RemoteAddr, c.RemotePort)
	}
	if c.State != "ESTAB" {
		t.Errorf("state=%q", c.State)
	}
}

// /proc/net/tcp6 fixture: loopback ::1 -> ::1 established.
//
//	16-byte address, little-endian per 32-bit word. ::1 = ...00000001 (last word).
const procTCP6Fixture = `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:0050 00000000000000000000000001000000:01BB 01 0 0 0 0 0 0 0
`

func TestParseProcNetTCP6Loopback(t *testing.T) {
	conns := ParseProcNet(procTCP6Fixture, "tcp", true)
	if len(conns) != 1 {
		t.Fatalf("want 1 conn, got %d: %+v", len(conns), conns)
	}
	if conns[0].RemoteAddr.String() != "::1" || conns[0].RemotePort != 443 {
		t.Errorf("remote=%s:%d want ::1:443", conns[0].RemoteAddr, conns[0].RemotePort)
	}
}

func TestParseProcNetUDPKeepsUnconn(t *testing.T) {
	// UDP rows have st 07 (UNCONN) but a real remote -> kept (proto != tcp gate).
	udp := "  sl local rem st\n   0: 0500A8C0:A8F2 01010101:0035 07 0 0 0 0 0 0 0 11\n"
	conns := ParseProcNet(udp, "udp", false)
	if len(conns) != 1 || conns[0].RemoteAddr.String() != "1.1.1.1" || conns[0].RemotePort != 53 {
		t.Errorf("udp conns=%+v", conns)
	}
}
