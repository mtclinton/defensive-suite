package triage

import (
	"reflect"
	"sort"
	"testing"
)

// Row 1 is a SOCK_RAW(3) socket; row 2 is a benign SOCK_DGRAM(2). Note both have
// Running=1 here on purpose: PACKET_SOCK_RUNNING is set for ANY bound/active
// packet socket (e.g. dhclient's SOCK_DGRAM), so it is NOT a filter flag and the
// raw/dgram distinction (Type), not R, is what selects the BPFDoor surface.
const packetFixture = `sk               RefCnt Type Proto  Iface R Rmem   User   Inode
ffff8a1b2c3d4e00 3      3    0003   2     1 0      0      34567
ffff8a1b2c3d5f00 3      2    0000   0     1 0      1000   99999
`

func TestParsePacketSockets(t *testing.T) {
	socks := ParsePacketSockets(packetFixture)
	if len(socks) != 2 {
		t.Fatalf("want 2 sockets, got %d: %+v", len(socks), socks)
	}
	// Row 1: SOCK_RAW(3), ETH_P_ALL(0x0003) -> raw packet-capture surface.
	s0 := socks[0]
	if s0.Type != 3 || s0.Protocol != 0x0003 || !s0.IsRaw || s0.Inode != 34567 {
		t.Errorf("row0=%+v", s0)
	}
	// Row 2: SOCK_DGRAM(2) -> NOT raw, despite Running=1 (R is not a filter flag).
	if socks[1].IsRaw || socks[1].Inode != 99999 {
		t.Errorf("row1=%+v", socks[1])
	}
	if socks[1].Running != 1 {
		t.Errorf("row1 Running should be parsed as 1: %+v", socks[1])
	}
}

func TestParsePacketSocketsNoHeaderAndGarbage(t *testing.T) {
	// No header, plus a short/garbage line that must be skipped.
	text := "garbage line\nffff00 3 3 0300 2 1 0 0 4242\n"
	socks := ParsePacketSockets(text)
	if len(socks) != 1 || socks[0].Inode != 4242 || !socks[0].IsRaw {
		t.Errorf("socks=%+v", socks)
	}
}

func TestRawSocketInodes(t *testing.T) {
	// Only the SOCK_RAW row's inode is returned; the SOCK_DGRAM row (even with
	// Running=1) is excluded — proving R no longer drives selection.
	got := RawSocketInodes(ParsePacketSockets(packetFixture))
	if !reflect.DeepEqual(got, []uint64{34567}) {
		t.Errorf("raw inodes=%v", got)
	}
}

func TestParseFDSocketInodes(t *testing.T) {
	links := map[string]string{
		"0": "/dev/null",
		"3": "socket:[34567]",
		"4": "socket:[99999]",
		"5": "anon_inode:[eventpoll]",
		"6": "socket:[notanumber]",
	}
	got := ParseFDSocketInodes(links)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if !reflect.DeepEqual(got, []uint64{34567, 99999}) {
		t.Errorf("inodes=%v", got)
	}
}

func TestExeIsDeleted(t *testing.T) {
	cases := map[string]bool{
		"/usr/bin/bash":             false,
		"/tmp/x (deleted)":          true,
		"/memfd:foo (deleted)":      true,
		"/memfd:bar":                true,
		"":                          false,
		"  /opt/app  ":              false,
		"/home/u/app.bin (deleted)": true,
	}
	for in, want := range cases {
		if got := ExeIsDeleted(in); got != want {
			t.Errorf("ExeIsDeleted(%q)=%v want %v", in, got, want)
		}
	}
}

func TestParseStatComm(t *testing.T) {
	if c, ok := ParseStatComm("1234 (sshd) S 1 1234"); !ok || c != "sshd" {
		t.Errorf("comm=%q ok=%v", c, ok)
	}
	if c, ok := ParseStatComm("99 (weird (name)) S 1"); !ok || c != "weird (name)" {
		t.Errorf("comm=%q ok=%v", c, ok)
	}
	if _, ok := ParseStatComm("no parens"); ok {
		t.Error("should fail without parens")
	}
}

func TestParseStatusUID(t *testing.T) {
	status := "Name:\tudevd\nState:\tS\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
	if uid, ok := ParseStatusUID(status); !ok || uid != 0 {
		t.Errorf("uid=%d ok=%v", uid, ok)
	}
	status2 := "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n"
	if uid, ok := ParseStatusUID(status2); !ok || uid != 1000 {
		t.Errorf("uid=%d ok=%v", uid, ok)
	}
	if _, ok := ParseStatusUID("Name:\tx\n"); ok {
		t.Error("missing Uid line should report not-ok")
	}
}

func TestWchanIsPacketRecv(t *testing.T) {
	for _, w := range []string{"packet_recvmsg", "packet_read", " packet_recvmsg\n"} {
		if !WchanIsPacketRecv(w) {
			t.Errorf("WchanIsPacketRecv(%q) should be true", w)
		}
	}
	for _, w := range []string{"0", "", "poll_schedule_timeout", "ep_poll"} {
		if WchanIsPacketRecv(w) {
			t.Errorf("WchanIsPacketRecv(%q) should be false", w)
		}
	}
}

// Regression: WchanIsPacketRecv must iterate blockedFuncs (not a hardcoded pair),
// so extending blockedFuncs covers the wchan path too. Temporarily add a symbol
// and confirm both wchan and stack recognize it.
func TestWchanIsPacketRecvHonorsBlockedFuncs(t *testing.T) {
	orig := blockedFuncs
	defer func() { blockedFuncs = orig }()
	blockedFuncs = append(append([]string{}, orig...), "tpacket_rcv")

	if !WchanIsPacketRecv("tpacket_rcv") {
		t.Error("wchan path must honor newly-added blockedFuncs entry")
	}
	if !StackBlockedInPacketRecv("[<0>] tpacket_rcv+0x10/0x80\n") {
		t.Error("stack path must honor newly-added blockedFuncs entry")
	}
	// And a symbol not in the (extended) list still does not match.
	if WchanIsPacketRecv("ep_poll") {
		t.Error("unrelated symbol must not match")
	}
}

func TestStackBlockedInPacketRecv(t *testing.T) {
	stack := "[<0>] __schedule+0x2c0/0x900\n[<0>] schedule+0x55/0xc0\n[<0>] packet_recvmsg+0x1a0/0x4d0\n[<0>] sock_recvmsg+0x6e/0x70\n"
	if !StackBlockedInPacketRecv(stack) {
		t.Error("stack with packet_recvmsg frame should match")
	}
	benign := "[<0>] __schedule+0x2c0/0x900\n[<0>] futex_wait_queue+0x60/0x90\n"
	if StackBlockedInPacketRecv(benign) {
		t.Error("benign futex stack should not match")
	}
}

func TestIsZeroByteMutex(t *testing.T) {
	if !IsZeroByteMutex(true, 0) {
		t.Error("regular zero-byte file is a mutex candidate")
	}
	if IsZeroByteMutex(true, 5) {
		t.Error("non-empty file is not a zero-byte mutex")
	}
	if IsZeroByteMutex(false, 0) {
		t.Error("directory/symlink should not match even at size 0")
	}
}

// Regression for the R-column false positive: a bare raw socket on a benign
// process (real exe, not blocked) must NOT be Critical. It is High "review",
// because /proc cannot confirm a filter and raw sockets are common (tcpdump).
func TestEvaluateProcessBareRawSocketIsHighReviewNotCritical(t *testing.T) {
	p := Process{PID: 9, Comm: "tcpdump", UID: 0, ExeTarget: "/usr/bin/tcpdump",
		RawInodes: []uint64{34567}}
	fs := evaluateProcess(p)
	if len(fs) != 1 {
		t.Fatalf("want exactly one raw-socket finding: %+v", fs)
	}
	if fs[0].Severity == 4 /*critical*/ {
		t.Errorf("uncorroborated bare raw socket must NOT be Critical: %+v", fs[0])
	}
	if fs[0].Severity != 3 /*high*/ || fs[0].Technique != "T1205.002" {
		t.Errorf("bare raw socket should be a single High review finding: %+v", fs[0])
	}
	if fs[0].Path != "/proc/9" {
		t.Errorf("path=%q", fs[0].Path)
	}
}

// Corroboration escalates the raw socket to Critical: raw socket + deleted exe.
func TestEvaluateProcessRawSocketCorroboratedIsCritical(t *testing.T) {
	p := Process{PID: 9, Comm: "x", ExeTarget: "/tmp/x (deleted)", RawInodes: []uint64{1}}
	var criticalRaw, criticalDeleted bool
	for _, f := range evaluateProcess(p) {
		if f.Technique == "T1205.002" && f.Severity == 4 {
			criticalRaw = true
		}
		if f.Technique == "T1620" && f.Severity == 4 {
			criticalDeleted = true // deleted exe escalates to critical when a raw socket is held
		}
	}
	if !criticalRaw || !criticalDeleted {
		t.Errorf("raw socket + deleted exe should both be critical; got raw=%v deleted=%v", criticalRaw, criticalDeleted)
	}
}

// Corroboration via the packet_recvmsg block also escalates the raw socket.
func TestEvaluateProcessRawSocketWithBlockIsCritical(t *testing.T) {
	p := Process{PID: 9, Comm: "x", ExeTarget: "/usr/bin/x", Wchan: "packet_recvmsg",
		RawInodes: []uint64{1}}
	var criticalRaw bool
	for _, f := range evaluateProcess(p) {
		if f.Technique == "T1205.002" && f.Severity == 4 && f.Rule == "egresswatch-magic-packet" {
			criticalRaw = true
		}
	}
	if !criticalRaw {
		t.Errorf("raw socket + packet_recvmsg block should be critical: %+v", evaluateProcess(p))
	}
}

func TestEvaluateProcessCleanProducesNothing(t *testing.T) {
	p := Process{PID: 1, Comm: "systemd", UID: 0, ExeTarget: "/usr/lib/systemd/systemd", Wchan: "ep_poll"}
	if fs := evaluateProcess(p); len(fs) != 0 {
		t.Errorf("clean process should produce no findings: %+v", fs)
	}
}

func TestEvaluateProcessBlockedNoRawSocketIsMedium(t *testing.T) {
	p := Process{PID: 9, Comm: "x", ExeTarget: "/usr/bin/x", Wchan: "packet_recvmsg"}
	fs := evaluateProcess(p)
	if len(fs) != 1 || fs[0].Severity != 2 /*medium*/ {
		t.Errorf("blocked-without-raw-socket should be a single medium: %+v", fs)
	}
}
