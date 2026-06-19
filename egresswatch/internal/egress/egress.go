// Package egress implements the expected-egress allowlist evaluator: given an
// allowlist (CIDRs, hostnames, ports for package mirrors, Tailscale, known
// services) and a list of observed outbound connections, it flags every
// connection not on the allowlist. This is the OpenSnitch allow/deny decision
// model expressed as data plus a pure evaluator — no kernel, no daemon.
//
// All decision logic is pure and table-tested; the only I/O is parsing the
// observed-connection text (ss / /proc/net) and loading the allowlist JSON.
package egress

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// Conn is one observed outbound connection.
type Conn struct {
	Proto      string // "tcp" | "udp"
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemoteAddr netip.Addr
	RemotePort uint16
	State      string // e.g. "ESTAB"; UDP rows have none
	Process    string // "comm/pid" when available, else ""
}

// String renders a connection for finding details.
func (c Conn) String() string {
	proc := c.Process
	if proc == "" {
		proc = "-"
	}
	return fmt.Sprintf("%s %s:%d->%s:%d %s proc=%s",
		c.Proto, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort, c.State, proc)
}

// Rule is one allowlist entry. A connection matches when every populated field
// matches: an empty/zero field means "any". CIDR and Host are mutually used —
// CIDR matches the remote IP, Host is recorded for documentation and matched
// against any names the caller pre-resolved into ResolvedIPs.
type Rule struct {
	Name        string   `json:"name"`                   // human label (e.g. "debian-mirror")
	CIDR        string   `json:"cidr,omitempty"`         // e.g. "100.64.0.0/10" (Tailscale CGNAT)
	Host        string   `json:"host,omitempty"`         // documentation / pre-resolution key
	ResolvedIPs []string `json:"resolved_ips,omitempty"` // optional pre-resolved IPs for Host
	Proto       string   `json:"proto,omitempty"`        // "tcp" | "udp" | "" (any)
	Ports       []uint16 `json:"ports,omitempty"`        // allowed remote ports; empty => any

	prefix    netip.Prefix // parsed CIDR
	hasPrefix bool
	resolved  []netip.Addr
}

// Allowlist is the parsed expected-egress policy plus a few convenience toggles.
type Allowlist struct {
	// AllowLoopback accepts connections whose remote is a loopback address
	// (127.0.0.0/8, ::1) without an explicit rule. Default true.
	AllowLoopback bool `json:"allow_loopback"`
	// AllowPrivate accepts RFC1918 / ULA / link-local remotes without a rule.
	// Off by default — lateral movement to private hosts is in scope.
	AllowPrivate bool   `json:"allow_private"`
	Rules        []Rule `json:"rules"`
}

// ParseAllowlist parses the allowlist JSON and precompiles each rule's CIDR and
// resolved IPs. A malformed CIDR is a hard error so a typo can't silently widen
// the policy to "match nothing / match everything".
func ParseAllowlist(data []byte) (Allowlist, error) {
	var al Allowlist
	al.AllowLoopback = true // default-on; JSON may override to false below
	if err := json.Unmarshal(data, &al); err != nil {
		return Allowlist{}, err
	}
	for i := range al.Rules {
		r := &al.Rules[i]
		if r.CIDR != "" {
			p, err := netip.ParsePrefix(r.CIDR)
			if err != nil {
				return Allowlist{}, fmt.Errorf("rule %q: bad cidr %q: %w", r.Name, r.CIDR, err)
			}
			r.prefix = p.Masked()
			r.hasPrefix = true
		}
		for _, s := range r.ResolvedIPs {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return Allowlist{}, fmt.Errorf("rule %q: bad resolved ip %q: %w", r.Name, s, err)
			}
			r.resolved = append(r.resolved, a)
		}
	}
	return al, nil
}

// portAllowed reports whether port is in the rule's port set (empty => any).
func (r Rule) portAllowed(port uint16) bool {
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// protoAllowed reports whether proto matches the rule (empty => any).
func (r Rule) protoAllowed(proto string) bool {
	return r.Proto == "" || strings.EqualFold(r.Proto, proto)
}

// Matches reports whether the rule permits the connection. A rule with neither a
// CIDR nor resolved IPs matches on proto+port alone (a "port 443 anywhere" rule).
func (r Rule) Matches(c Conn) bool {
	if !r.protoAllowed(c.Proto) || !r.portAllowed(c.RemotePort) {
		return false
	}
	if !r.hasPrefix && len(r.resolved) == 0 {
		// Address-agnostic rule: proto+port already matched.
		return true
	}
	if r.hasPrefix && r.RemoteInPrefix(c.RemoteAddr) {
		return true
	}
	for _, a := range r.resolved {
		if a == c.RemoteAddr {
			return true
		}
	}
	return false
}

// RemoteInPrefix reports whether addr falls inside the rule's CIDR, normalizing
// 4-in-6 mapped addresses so a v4 connection matches a v4 CIDR.
func (r Rule) RemoteInPrefix(addr netip.Addr) bool {
	if !r.hasPrefix {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return r.prefix.Contains(addr)
}

// Decision is the verdict for one observed connection.
type Decision struct {
	Conn    Conn
	Allowed bool
	RuleHit string // name of the matching rule, or "" when denied
	Reason  string // why allowed/denied (for the finding detail)
}

// Evaluate decides one connection against the allowlist. It is the pure core:
// no I/O, fully table-tested.
func (al Allowlist) Evaluate(c Conn) Decision {
	// Unspecified / zero remote (e.g. a listening socket misclassified, or a
	// connecting socket with no peer yet) is not egress — allow silently.
	if !c.RemoteAddr.IsValid() || c.RemoteAddr.IsUnspecified() {
		return Decision{Conn: c, Allowed: true, Reason: "no remote peer (not egress)"}
	}
	ra := c.RemoteAddr
	if ra.Is4In6() {
		ra = ra.Unmap()
	}
	if al.AllowLoopback && ra.IsLoopback() {
		return Decision{Conn: c, Allowed: true, Reason: "loopback"}
	}
	if al.AllowPrivate && (ra.IsPrivate() || ra.IsLinkLocalUnicast() || ra.IsLinkLocalMulticast()) {
		return Decision{Conn: c, Allowed: true, Reason: "private/link-local (allow_private)"}
	}
	for _, r := range al.Rules {
		if r.Matches(c) {
			return Decision{Conn: c, Allowed: true, RuleHit: r.Name, Reason: "rule:" + r.Name}
		}
	}
	return Decision{Conn: c, Allowed: false, Reason: "no allowlist rule matched"}
}

// EvaluateAll returns the decision for every observed connection, in order.
func (al Allowlist) EvaluateAll(conns []Conn) []Decision {
	out := make([]Decision, 0, len(conns))
	for _, c := range conns {
		out = append(out, al.Evaluate(c))
	}
	return out
}
