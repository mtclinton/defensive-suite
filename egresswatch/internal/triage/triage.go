// Package triage implements a pure-Go BPFDoor/Symbiote triage scanner, modelled
// on Rapid7's rapid7_detect_bpfdoor.sh. It reads a configurable /proc root and
// flags the documented passive-backdoor markers:
//
//  1. A process holding a raw / AF_PACKET (SOCK_RAW) socket — the surface a
//     BPFDoor-class implant uses for traffic-signalling (T1205.002). A bare raw
//     socket alone is common and benign (tcpdump, dhclient, lldpd); it is rated
//     Critical only when corroborated by another marker. Whether a *BPF filter*
//     is actually attached cannot be read from /proc — that confirmation is the
//     eBPF sensor's job, not this pure-Go triage.
//  2. A fileless executable: /proc/<pid>/exe resolving to a "(deleted)" path
//     (T1620, reflective/anonymous execution).
//  3. Zero-byte mutex/lock files the implant uses as a single-instance guard.
//  4. A thread blocked in packet_recvmsg (waiting on the magic packet), read
//     from /proc/<pid>/stack or /proc/<pid>/wchan.
//
// Every parser is a pure function over fixture text so the detection logic is
// testable without a live kernel. Scan only does the filesystem I/O plumbing.
package triage

import (
	"bufio"
	"strconv"
	"strings"
)

// PacketSocket is one row of /proc/net/packet: an AF_PACKET socket. The Running
// column is PACKET_SOCK_RUNNING — the kernel sets it for ANY bound/active packet
// socket (tcpdump, dhclient/dhcpcd, lldpd, NetworkManager). It is NOT the
// SO_ATTACH_FILTER flag and does NOT indicate an attached BPF filter; /proc
// exposes no "filter attached" bit. The load-bearing BPFDoor field here is
// instead Type==SOCK_RAW(3): the raw-socket surface the implant uses.
type PacketSocket struct {
	Inode    uint64 // socket inode, cross-referenced with /proc/<pid>/fd
	Type     int    // SOCK_RAW(3) / SOCK_DGRAM(2)
	Protocol int    // ETH_P_* (e.g. 0x300 ETH_P_ALL); 0 is common for BPFDoor
	Running  int    // PACKET_SOCK_RUNNING: socket is bound/active (NOT a filter)
	IsRaw    bool   // true when Type == SOCK_RAW(3): the raw packet-capture surface
}

// ParsePacketSockets parses /proc/net/packet text. Columns (kernel af_packet.c
// packet_seq_show), header then one row per socket:
//
//	sk       RefCnt Type Proto  Iface R Rmem   User   Inode
//	ffff...  3      3    0003   2     1 0      0      34567
//
// The R column is PACKET_SOCK_RUNNING (socket bound/active), not a filter flag.
// The Type column distinguishes SOCK_RAW(3) from SOCK_DGRAM(2). The last field
// is the inode.
func ParsePacketSockets(text string) []PacketSocket {
	var out []PacketSocket
	sc := bufio.NewScanner(strings.NewReader(text))
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if first {
			// Skip the header row if present (starts with "sk").
			first = false
			if len(fields) > 0 && (fields[0] == "sk" || strings.HasPrefix(fields[0], "sk")) {
				continue
			}
		}
		// Need at least: sk RefCnt Type Proto Iface R Rmem User Inode (9 cols).
		if len(fields) < 9 {
			continue
		}
		ps := PacketSocket{}
		ps.Type = atoiBase(fields[2], 10)
		ps.Protocol = atoiBase(fields[3], 16) // proto printed as 4-hex (%04x)
		ps.Running = atoiBase(fields[5], 10)
		ps.Inode = atou(fields[8])
		ps.IsRaw = ps.Type == 3 // SOCK_RAW
		out = append(out, ps)
	}
	return out
}

// RawSocketInodes returns the inodes of AF_PACKET SOCK_RAW sockets. These are
// the raw packet-capture sockets to chase back to a PID via /proc/<pid>/fd; a
// PID owning one is the BPFDoor-class surface (corroborate before rating it
// Critical — see evaluateProcess). /proc cannot tell us whether a BPF filter is
// attached, so this is deliberately the raw-socket set, not a "filtered" set.
func RawSocketInodes(socks []PacketSocket) []uint64 {
	var out []uint64
	for _, s := range socks {
		if s.IsRaw && s.Inode != 0 {
			out = append(out, s.Inode)
		}
	}
	return out
}

// ParseFDSocketInodes extracts socket inodes from the readlink targets of a
// process's fd entries. Each target looks like "socket:[34567]". The input maps
// fd name -> link target, as produced by reading /proc/<pid>/fd.
func ParseFDSocketInodes(links map[string]string) []uint64 {
	var out []uint64
	for _, target := range links {
		if ino, ok := socketInode(target); ok {
			out = append(out, ino)
		}
	}
	return out
}

// socketInode parses "socket:[NNN]" -> NNN.
func socketInode(target string) (uint64, bool) {
	const pre = "socket:["
	if !strings.HasPrefix(target, pre) || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	mid := target[len(pre) : len(target)-1]
	n, err := strconv.ParseUint(mid, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ExeIsDeleted reports whether a /proc/<pid>/exe readlink target indicates a
// fileless / anonymous executable. The kernel appends " (deleted)" when the
// backing file is gone, and memfd-backed execs show as "/memfd:...(deleted)".
func ExeIsDeleted(exeTarget string) bool {
	t := strings.TrimSpace(exeTarget)
	if t == "" {
		return false
	}
	return strings.HasSuffix(t, "(deleted)") || strings.HasPrefix(t, "/memfd:")
}

// ParseStatComm extracts the comm field from /proc/<pid>/stat content, which is
// the text inside the first '('...last ')' pair (it may itself contain spaces).
func ParseStatComm(stat string) (string, bool) {
	open := strings.IndexByte(stat, '(')
	closeIdx := strings.LastIndexByte(stat, ')')
	if open < 0 || closeIdx < 0 || closeIdx <= open+1 {
		return "", false
	}
	return stat[open+1 : closeIdx], true
}

// ParseStatusUID returns the real UID from /proc/<pid>/status ("Uid:\tR E S F").
func ParseStatusUID(status string) (int, bool) {
	sc := bufio.NewScanner(strings.NewReader(status))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if n, err := strconv.Atoi(f[1]); err == nil {
					return n, true
				}
			}
		}
	}
	return 0, false
}

// blockedFuncs are the kernel symbols a thread sleeps in while waiting for the
// magic packet on a raw/packet socket. wchan/stack hitting one of these is the
// "blocked in packet_recvmsg" marker from the Rapid7 triage.
var blockedFuncs = []string{
	"packet_recvmsg",
	"packet_read", // older naming on some trees
}

// WchanIsPacketRecv reports whether a /proc/<pid>/wchan value names the packet
// receive path. wchan is a single symbol name (e.g. "packet_recvmsg") or "0".
// It iterates blockedFuncs (the same set StackBlockedInPacketRecv uses) so
// extending that list covers the wchan path too.
func WchanIsPacketRecv(wchan string) bool {
	w := strings.TrimSpace(wchan)
	if w == "" || w == "0" {
		return false
	}
	for _, fn := range blockedFuncs {
		if w == fn {
			return true
		}
	}
	return false
}

// StackBlockedInPacketRecv reports whether a /proc/<pid>/stack dump shows a frame
// in the packet receive path. Each line looks like "[<0>] packet_recvmsg+0x...".
func StackBlockedInPacketRecv(stack string) bool {
	sc := bufio.NewScanner(strings.NewReader(stack))
	for sc.Scan() {
		line := sc.Text()
		for _, fn := range blockedFuncs {
			if strings.Contains(line, fn) {
				return true
			}
		}
	}
	return false
}

// IsZeroByteMutex reports whether a candidate lock/mutex file is the zero-byte
// single-instance guard BPFDoor-class implants drop (e.g. /var/run/haldrund.pid,
// /dev/shm/.<x>). The caller supplies the file size and whether it is a regular
// file; this keeps the predicate pure and testable.
func IsZeroByteMutex(isRegular bool, size int64) bool {
	return isRegular && size == 0
}

// atoiBase parses s in the given base, returning 0 on error (proc fields are
// well-formed; a malformed line is simply scored as zero rather than aborting).
func atoiBase(s string, base int) int {
	n, err := strconv.ParseInt(strings.TrimSpace(s), base, 64)
	if err != nil {
		return 0
	}
	return int(n)
}

func atou(s string) uint64 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
