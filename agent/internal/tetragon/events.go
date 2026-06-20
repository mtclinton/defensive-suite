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

type execEvent struct {
	Process process `json:"process"`
	Parent  process `json:"parent"`
}

type pathArg struct {
	Path string `json:"path"`
}

type kprobeArg struct {
	FileArg   *pathArg `json:"file_arg"`
	PathArg   *pathArg `json:"path_arg"`
	StringArg *string  `json:"string_arg"`
	IntArg    *int64   `json:"int_arg"`
}

type kprobeEvent struct {
	Process      process     `json:"process"`
	Parent       process     `json:"parent"`
	FunctionName string      `json:"function_name"`
	PolicyName   string      `json:"policy_name"`
	Action       string      `json:"action"`
	Args         []kprobeArg `json:"args"`
}

type rawEvent struct {
	ProcessExec   *execEvent   `json:"process_exec"`
	ProcessExit   *execEvent   `json:"process_exit"`
	ProcessKprobe *kprobeEvent `json:"process_kprobe"`
	NodeName      string       `json:"node_name"`
	Time          string       `json:"time"`
}

// Event is the normalized form. Paths holds any file paths referenced by a
// kprobe's arguments; Ints holds any integer arguments in their original order
// (e.g. the LSM mask for security_file_permission, where bit MAY_WRITE=2
// distinguishes a write from a read/exec).
type Event struct {
	Kind     string // "exec", "exit", "kprobe"
	Binary   string
	Args     string
	Pid      uint32
	UID      uint32
	Cwd      string
	Flags    string
	Parent   string
	Function string
	Policy   string
	Action   string
	Paths    []string
	Ints     []int64
	Node     string
	Time     string
}

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
	e := Event{Node: r.NodeName, Time: r.Time}
	switch {
	case r.ProcessExec != nil:
		p := r.ProcessExec.Process
		e.Kind, e.Binary, e.Args = "exec", p.Binary, p.Arguments
		e.Pid, e.UID, e.Cwd, e.Flags = p.Pid, p.UID, p.Cwd, p.Flags
		e.Parent = r.ProcessExec.Parent.Binary
	case r.ProcessExit != nil:
		p := r.ProcessExit.Process
		e.Kind, e.Binary, e.Pid, e.UID = "exit", p.Binary, p.Pid, p.UID
	case r.ProcessKprobe != nil:
		k := r.ProcessKprobe
		e.Kind, e.Binary, e.Pid, e.UID = "kprobe", k.Process.Binary, k.Process.Pid, k.Process.UID
		e.Function, e.Policy, e.Action, e.Parent = k.FunctionName, k.PolicyName, k.Action, k.Parent.Binary
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
