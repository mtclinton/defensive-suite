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
// kprobe's arguments.
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
	Node     string
	Time     string
}

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
			}
		}
	default:
		return Event{}, false
	}
	return e, true
}

// ParseStream yields normalized events from a reader of JSON lines, skipping
// anything malformed. It tolerates long lines.
func ParseStream(r io.Reader) []Event {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if e, ok := ParseLine(sc.Text()); ok {
			out = append(out, e)
		}
	}
	return out
}
