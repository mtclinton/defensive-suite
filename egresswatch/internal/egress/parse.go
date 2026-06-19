package egress

import (
	"bufio"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
)

// outboundStates are the TCP states that represent an active or pending egress
// connection. LISTEN is excluded (it is inbound), as are the closing states.
var outboundStates = map[string]bool{
	"ESTAB":       true,
	"SYN-SENT":    true,
	"SYN_SENT":    true,
	"ESTABLISHED": true,
}

// ParseSS parses the output of `ss -tunp` (or `ss -tunap`). Example line:
//
//	tcp   ESTAB  0 0  192.168.1.5:54321  140.82.112.3:443  users:(("curl",pid=42,fd=3))
//
// The header line and LISTEN sockets are skipped. UDP rows have an empty state
// column in the netid form; ss prints "UNCONN" for them, which we keep as the
// state and treat as egress when a real remote peer is present.
func ParseSS(text string) []Conn {
	var conns []Conn
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Header: "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port".
		if fields[0] == "Netid" || strings.EqualFold(fields[0], "State") {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		state := fields[1]
		if proto == "tcp" && !outboundStates[strings.ToUpper(state)] {
			continue // LISTEN, TIME-WAIT, etc. are not active egress
		}
		// Local and peer are fields[4] and fields[5] (after Netid State Recv Send).
		if len(fields) < 6 {
			continue
		}
		la, lp, ok1 := splitAddrPort(fields[4])
		ra, rp, ok2 := splitAddrPort(fields[5])
		if !ok1 || !ok2 {
			continue
		}
		c := Conn{
			Proto: proto, LocalAddr: la, LocalPort: lp,
			RemoteAddr: ra, RemotePort: rp, State: strings.ToUpper(state),
		}
		if len(fields) >= 7 {
			c.Process = parseSSUsers(fields[6])
		}
		conns = append(conns, c)
	}
	return conns
}

// parseSSUsers extracts "comm/pid" from ss's users:(("comm",pid=N,fd=M)) field.
func parseSSUsers(s string) string {
	i := strings.Index(s, `(("`)
	if i < 0 {
		return ""
	}
	rest := s[i+3:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	comm := rest[:end]
	pid := ""
	if j := strings.Index(rest, "pid="); j >= 0 {
		k := j + 4
		for k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
			k++
		}
		pid = rest[j+4 : k]
	}
	if pid == "" {
		return comm
	}
	return comm + "/" + pid
}

// splitAddrPort splits an "address:port" token from ss into a netip.Addr and a
// port. It handles IPv6 ("[::1]:443" and the bracket-less "fe80::1%eth0:443"
// form ss sometimes prints) and the "*:*" wildcard. The address may carry a
// "%zone" scope which is stripped.
func splitAddrPort(tok string) (netip.Addr, uint16, bool) {
	tok = strings.TrimSpace(tok)
	colon := strings.LastIndexByte(tok, ':')
	if colon < 0 {
		return netip.Addr{}, 0, false
	}
	host := tok[:colon]
	portStr := tok[colon+1:]
	host = strings.Trim(host, "[]")
	if pct := strings.IndexByte(host, '%'); pct >= 0 {
		host = host[:pct]
	}
	if host == "*" || host == "" {
		// Unspecified remote (a wildcard/listening or not-yet-connected socket).
		port, _ := parsePort(portStr)
		return netip.IPv4Unspecified(), port, true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	port, ok := parsePort(portStr)
	if !ok {
		return netip.Addr{}, 0, false
	}
	return addr, port, true
}

func parsePort(s string) (uint16, bool) {
	if s == "*" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

// ParseProcNet parses /proc/net/tcp, tcp6, udp, or udp6 text. proto selects the
// label ("tcp"/"udp"); is6 selects 16-byte address decoding. Only sockets with a
// non-zero remote address are returned (a zero remote is a listener). For TCP,
// only ESTABLISHED(01) and SYN_SENT(02) rows are kept as active egress.
//
// Columns (kernel): sl local_address rem_address st ... inode ...
// Addresses are hex, little-endian per 32-bit word.
func ParseProcNet(text, proto string, is6 bool) []Conn {
	var conns []Conn
	sc := bufio.NewScanner(strings.NewReader(text))
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if strings.HasPrefix(line, "sl") {
				continue // header
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		la, lp, ok1 := parseHexAddr(fields[1], is6)
		ra, rp, ok2 := parseHexAddr(fields[2], is6)
		if !ok1 || !ok2 {
			continue
		}
		st := fields[3]
		if proto == "tcp" && st != "01" && st != "02" {
			continue // not ESTABLISHED / SYN_SENT
		}
		if ra.IsUnspecified() || rp == 0 {
			continue // listener / no peer
		}
		conns = append(conns, Conn{
			Proto: proto, LocalAddr: la, LocalPort: lp,
			RemoteAddr: ra, RemotePort: rp, State: procState(st),
		})
	}
	return conns
}

// procState maps the hex TCP state byte to a short label for the report detail.
func procState(st string) string {
	switch st {
	case "01":
		return "ESTAB"
	case "02":
		return "SYN-SENT"
	default:
		return "ST" + st
	}
}

// parseHexAddr decodes a "HEXADDR:HEXPORT" token from /proc/net/*. The address is
// a hex string in host byte order per 32-bit word (little-endian on x86); we
// reverse each 4-byte word to recover network-order bytes, then build the Addr.
func parseHexAddr(tok string, is6 bool) (netip.Addr, uint16, bool) {
	parts := strings.SplitN(tok, ":", 2)
	if len(parts) != 2 {
		return netip.Addr{}, 0, false
	}
	portN, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	hexAddr := parts[0]
	want := 8
	if is6 {
		want = 32
	}
	if len(hexAddr) != want {
		return netip.Addr{}, 0, false
	}
	raw := make([]byte, want/2)
	for i := 0; i < len(raw); i++ {
		b, err := strconv.ParseUint(hexAddr[i*2:i*2+2], 16, 8)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		raw[i] = byte(b)
	}
	// Each consecutive 4-byte word is little-endian; swap to network order.
	for w := 0; w+4 <= len(raw); w += 4 {
		le := binary.LittleEndian.Uint32(raw[w : w+4])
		binary.BigEndian.PutUint32(raw[w:w+4], le)
	}
	var addr netip.Addr
	if is6 {
		var a16 [16]byte
		copy(a16[:], raw)
		addr = netip.AddrFrom16(a16)
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
	} else {
		var a4 [4]byte
		copy(a4[:], raw)
		addr = netip.AddrFrom4(a4)
	}
	return addr, uint16(portN), true
}
