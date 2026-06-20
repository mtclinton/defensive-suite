// Package tetragon parses Tetragon's JSON event export into a normalized form the
// rules engine consumes. It reads the `tetra getevents -o json` / log-export
// shape: one JSON object per line, keyed by event type (process_exec,
// process_exit, process_kprobe). Unknown/malformed lines are skipped.
package tetragon

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

type process struct {
	ExecID    string `json:"exec_id"`
	Pid       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
	Cwd       string `json:"cwd"`
	Binary    string `json:"binary"`
	Arguments string `json:"arguments"`
	Flags     string `json:"flags"`
}

// UnmarshalJSON accepts both the snake_case (`exec_id`) and camelCase (`execId`)
// process shapes Tetragon emits across its exports, so exec_id is populated
// regardless of which one a given deployment writes.
func (p *process) UnmarshalJSON(b []byte) error {
	type alias process // avoid recursion
	var a struct {
		alias
		ExecIDCamel string `json:"execId"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*p = process(a.alias)
	if p.ExecID == "" && a.ExecIDCamel != "" {
		p.ExecID = a.ExecIDCamel
	}
	return nil
}

type execEvent struct {
	Process process `json:"process"`
	Parent  process `json:"parent"`
}

type pathArg struct {
	Path string `json:"path"`
}

// sockArg is Tetragon's KprobeSock argument (declared `type: "sock"` in a
// TracingPolicy). The egress hook (tcp_connect / security_socket_connect)
// exports the destination as daddr/dport here. Tetragon's two export shapes use
// different field names for the destination, so all are accepted:
//   - the KprobeSock fields:        daddr / dport  (and saddr / sport / family …)
//   - some policies/exports rename:  destination_ip / destination_port
//
// Everything is best-effort: a missing/zero field just leaves Dst/DstPort empty,
// and an unknown shape degrades to no destination rather than crashing.
type sockArg struct {
	Daddr    string `json:"daddr"`
	Dport    uint32 `json:"dport"`
	Saddr    string `json:"saddr"`
	Sport    uint32 `json:"sport"`
	Family   string `json:"family"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	// Alternate field names some exports/policies use for the destination.
	DestinationIP   string `json:"destination_ip"`
	DestinationPort uint32 `json:"destination_port"`
}

// dst resolves the destination ip/port from whichever fields the export used.
func (s sockArg) dst() (ip string, port uint32) {
	ip, port = s.Daddr, s.Dport
	if ip == "" {
		ip = s.DestinationIP
	}
	if port == 0 {
		port = s.DestinationPort
	}
	return ip, port
}

// sockaddrArg is Tetragon's KprobeSockaddr argument (declared `type: "sockaddr"`
// in a TracingPolicy). The socket-syscall egress hooks (security_socket_connect
// / __sys_connect) carry the destination here — NOT in a sock_arg — as the
// connect() target address (sa_addr / sa_port). Best-effort: a missing/zero
// field just yields no destination.
type sockaddrArg struct {
	SaAddr string `json:"sa_addr"`
	SaPort uint32 `json:"sa_port"`
	Family string `json:"sa_family"`
}

// dst resolves the destination ip/port from the sockaddr fields.
func (s sockaddrArg) dst() (ip string, port uint32) {
	return s.SaAddr, s.SaPort
}

type kprobeArg struct {
	FileArg   *pathArg `json:"file_arg"`
	PathArg   *pathArg `json:"path_arg"`
	StringArg *string  `json:"string_arg"`
	IntArg    *int64   `json:"int_arg"`
	SockArg   *sockArg `json:"sock_arg"`
	// camelCase mirror of sock_arg for the ProtoJSON export shape.
	SockArgCamel *sockArg `json:"sockArg"`
	// SockaddrArg carries the connect() target for the socket-syscall egress
	// hooks (security_socket_connect / __sys_connect), which export the
	// destination in a sockaddr rather than a sock. SockaddrArgCamel mirrors it
	// for the ProtoJSON export shape.
	SockaddrArg      *sockaddrArg `json:"sockaddr_arg"`
	SockaddrArgCamel *sockaddrArg `json:"sockaddrArg"`
}

// sock returns the parsed socket argument under either field-name shape.
func (a kprobeArg) sock() *sockArg {
	if a.SockArg != nil {
		return a.SockArg
	}
	return a.SockArgCamel
}

// sockaddr returns the parsed sockaddr argument under either field-name shape.
func (a kprobeArg) sockaddr() *sockaddrArg {
	if a.SockaddrArg != nil {
		return a.SockaddrArg
	}
	return a.SockaddrArgCamel
}

type kprobeEvent struct {
	Process      process     `json:"process"`
	Parent       process     `json:"parent"`
	FunctionName string      `json:"function_name"`
	PolicyName   string      `json:"policy_name"`
	Action       string      `json:"action"`
	Args         []kprobeArg `json:"args"`
	// camelCase mirrors for the ProtoJSON export shape.
	FunctionNameCamel string `json:"functionName"`
	PolicyNameCamel   string `json:"policyName"`
}

// fn / policy return the function/policy name under either field-name shape.
func (k kprobeEvent) fn() string {
	if k.FunctionName != "" {
		return k.FunctionName
	}
	return k.FunctionNameCamel
}

func (k kprobeEvent) policy() string {
	if k.PolicyName != "" {
		return k.PolicyName
	}
	return k.PolicyNameCamel
}

type rawEvent struct {
	ProcessExec   *execEvent   `json:"process_exec"`
	ProcessExit   *execEvent   `json:"process_exit"`
	ProcessKprobe *kprobeEvent `json:"process_kprobe"`
	NodeName      string       `json:"node_name"`
	Time          string       `json:"time"`
	// camelCase mirrors for the ProtoJSON export shape.
	ProcessExecCamel   *execEvent   `json:"processExec"`
	ProcessExitCamel   *execEvent   `json:"processExit"`
	ProcessKprobeCamel *kprobeEvent `json:"processKprobe"`
	NodeNameCamel      string       `json:"nodeName"`
}

func (r rawEvent) exec() *execEvent {
	if r.ProcessExec != nil {
		return r.ProcessExec
	}
	return r.ProcessExecCamel
}

func (r rawEvent) exit() *execEvent {
	if r.ProcessExit != nil {
		return r.ProcessExit
	}
	return r.ProcessExitCamel
}

func (r rawEvent) kprobe() *kprobeEvent {
	if r.ProcessKprobe != nil {
		return r.ProcessKprobe
	}
	return r.ProcessKprobeCamel
}

func (r rawEvent) node() string {
	if r.NodeName != "" {
		return r.NodeName
	}
	return r.NodeNameCamel
}

// Event is the normalized form. Paths holds any file paths referenced by a
// kprobe's arguments; Ints holds any integer arguments in their original order
// (e.g. the LSM mask for security_file_permission, where bit MAY_WRITE=2
// distinguishes a write from a read/exec).
//
// ExecID / ParentExecID are Tetragon's stable per-execution identifiers
// (process.exec_id / parent.exec_id). Unlike Pid they are unique across pid
// reuse, so the correlator keys process lineage on them. Parent remains the
// parent BINARY name for back-compat; ParentExecID is the new lineage key.
//
// A "connect" Event is an egress network event from a tcp_connect /
// security_socket_connect kprobe: Dst/DstPort carry the destination the process
// reached out to, the signal the correlator pairs with a suspicious exec.
type Event struct {
	Kind         string // "exec", "exit", "kprobe", "connect"
	Binary       string
	Args         string
	Pid          uint32
	UID          uint32
	Cwd          string
	Flags        string
	Parent       string // parent binary name (back-compat)
	ExecID       string // Tetragon process.exec_id
	ParentExecID string // Tetragon parent.exec_id
	Function     string
	Policy       string
	Action       string
	Paths        []string
	Ints         []int64
	Dst          string // connect: destination IP
	DstPort      int    // connect: destination port
	Node         string
	Time         string
}

// egressFuncs are the kprobe function names that indicate an outbound network
// connection. A kprobe on any of these is normalized to a "connect" Event.
var egressFuncs = map[string]bool{
	"tcp_connect":             true,
	"security_socket_connect": true,
	"__sys_connect":           true,
	"__x64_sys_connect":       true,
}

// IsEgressFunc reports whether fn is an egress (outbound connect) hook.
func IsEgressFunc(fn string) bool { return egressFuncs[fn] }

// HasMask reports whether the event carries an integer mask argument (e.g. the
// security_file_permission LSM access mask). ParseLine records int args in Ints.
func (e Event) HasMask() bool { return len(e.Ints) > 0 }

// MayWrite reports whether the event's first integer mask argument has the
// MAY_WRITE bit (2) set. Only meaningful when HasMask is true.
func (e Event) MayWrite() bool { return len(e.Ints) > 0 && e.Ints[0]&0x2 != 0 }

// ParseLine parses one JSON event line. ok is false for blank/malformed/unknown.
func ParseLine(line string) (Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return Event{}, false
	}
	var r rawEvent
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		return Event{}, false
	}
	return normalize(r)
}

func normalize(r rawEvent) (Event, bool) {
	e := Event{Node: r.node(), Time: r.Time}
	switch {
	case r.exec() != nil:
		x := r.exec()
		p := x.Process
		e.Kind, e.Binary, e.Args = "exec", p.Binary, p.Arguments
		e.Pid, e.UID, e.Cwd, e.Flags = p.Pid, p.UID, p.Cwd, p.Flags
		e.ExecID, e.ParentExecID = p.ExecID, x.Parent.ExecID
		e.Parent = x.Parent.Binary
	case r.exit() != nil:
		x := r.exit()
		p := x.Process
		e.Kind, e.Binary, e.Pid, e.UID = "exit", p.Binary, p.Pid, p.UID
		e.ExecID, e.ParentExecID = p.ExecID, x.Parent.ExecID
	case r.kprobe() != nil:
		k := r.kprobe()
		e.Binary, e.Pid, e.UID = k.Process.Binary, k.Process.Pid, k.Process.UID
		e.Function, e.Policy, e.Action = k.fn(), k.policy(), k.Action
		e.Parent = k.Parent.Binary
		e.ExecID, e.ParentExecID = k.Process.ExecID, k.Parent.ExecID
		// An egress kprobe becomes a "connect" network Event so the correlator can
		// pair it with a suspicious exec; every other kprobe stays "kprobe".
		e.Kind = "kprobe"
		if IsEgressFunc(e.Function) {
			e.Kind = "connect"
		}
		for _, a := range k.Args {
			switch {
			case a.FileArg != nil && a.FileArg.Path != "":
				e.Paths = append(e.Paths, a.FileArg.Path)
			case a.PathArg != nil && a.PathArg.Path != "":
				e.Paths = append(e.Paths, a.PathArg.Path)
			case a.StringArg != nil && strings.HasPrefix(*a.StringArg, "/"):
				e.Paths = append(e.Paths, *a.StringArg)
			case a.IntArg != nil:
				e.Ints = append(e.Ints, *a.IntArg)
			case a.sock() != nil:
				// Primary: tcp_connect exports the destination in a sock_arg. An
				// unknown sock shape leaves Dst/DstPort empty rather than failing.
				if ip, port := a.sock().dst(); ip != "" || port != 0 {
					if e.Dst == "" {
						e.Dst = ip
					}
					if e.DstPort == 0 {
						e.DstPort = int(port)
					}
				}
			case a.sockaddr() != nil:
				// Fallback: the socket-syscall egress hooks
				// (security_socket_connect / __sys_connect) carry the destination
				// in a sockaddr_arg instead of a sock_arg.
				if ip, port := a.sockaddr().dst(); ip != "" || port != 0 {
					if e.Dst == "" {
						e.Dst = ip
					}
					if e.DstPort == 0 {
						e.DstPort = int(port)
					}
				}
			}
		}
	default:
		return Event{}, false
	}
	return e, true
}

// maxLineBytes caps a single event line. A line longer than this (e.g. an
// attacker-influenced huge argv) is SKIPPED, not fatal: parsing continues with
// the next line. bufio.Scanner instead returns ErrTooLong and STOPS, which would
// silently drop every subsequent event — exactly what an attacker wants.
const maxLineBytes = 8 * 1024 * 1024

// ParseStream yields normalized events from a reader of JSON lines, skipping
// anything malformed. An over-long line (> maxLineBytes) is dropped and parsing
// CONTINUES with the following lines, so one oversized event cannot suppress
// detection of everything after it. Memory stays bounded: lines are read through
// a fixed-size buffer in chunks, never materialized whole when over-long.
func ParseStream(r io.Reader) []Event {
	var out []Event
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := readLineBounded(br)
		if line != "" {
			if e, ok := ParseLine(line); ok {
				out = append(out, e)
			}
		}
		if err != nil {
			return out // io.EOF or a read error: stop.
		}
	}
}

// readLineBounded reads one '\n'-terminated line, capped at maxLineBytes, using
// ReadSlice so the reader's fixed internal buffer bounds memory. If the line
// exceeds the cap, its bytes are drained up to (and including) the next newline
// and "" is returned, so the caller skips it and proceeds. err is non-nil only
// on EOF or a genuine read error.
func readLineBounded(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	overLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if !overLong {
			if sb.Len()+len(chunk) > maxLineBytes {
				overLong = true
				sb.Reset() // release what we held; stop accumulating this line
			} else {
				sb.Write(chunk)
			}
		}
		switch err {
		case nil:
			// chunk ended in '\n': a complete line.
			if overLong {
				return "", nil // skipped: tell the caller to move on
			}
			return strings.TrimRight(sb.String(), "\n"), nil
		case bufio.ErrBufferFull:
			// Partial line filling the buffer with no newline yet: keep draining.
			continue
		default:
			// EOF or a read error: return whatever we have (unless over-long).
			if overLong {
				return "", err
			}
			return strings.TrimRight(sb.String(), "\n"), err
		}
	}
}
