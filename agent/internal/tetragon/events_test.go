package tetragon

import (
	"strings"
	"testing"
)

const execLine = `{"process_exec":{"process":{"pid":1337,"uid":0,"binary":"/tmp/.x/payload","arguments":"--beacon","cwd":"/tmp","flags":"execve rootcwd"},"parent":{"binary":"/bin/bash","pid":1000}},"node_name":"lab","time":"2026-06-19T00:00:00Z"}`

const bpfLoadLine = `{"process_kprobe":{"process":{"pid":2222,"uid":0,"binary":"/usr/bin/evil"},"parent":{"binary":"/bin/bash"},"function_name":"security_bpf_prog_load","policy_name":"bpf-observe","action":"KPROBE_ACTION_POST","args":[]},"node_name":"lab"}`

const writeLine = `{"process_kprobe":{"process":{"pid":3,"binary":"/usr/bin/tee"},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/etc/ld.so.preload"}}]}}`

func TestParseExec(t *testing.T) {
	e, ok := ParseLine(execLine)
	if !ok {
		t.Fatal("exec line should parse")
	}
	if e.Kind != "exec" || e.Binary != "/tmp/.x/payload" || e.Pid != 1337 {
		t.Errorf("event=%+v", e)
	}
	if e.Args != "--beacon" || e.Parent != "/bin/bash" || e.Node != "lab" {
		t.Errorf("event=%+v", e)
	}
}

func TestParseKprobeBPF(t *testing.T) {
	e, ok := ParseLine(bpfLoadLine)
	if !ok || e.Kind != "kprobe" {
		t.Fatalf("event=%+v ok=%v", e, ok)
	}
	if e.Function != "security_bpf_prog_load" || e.Binary != "/usr/bin/evil" || e.Policy != "bpf-observe" {
		t.Errorf("event=%+v", e)
	}
}

func TestParseKprobePath(t *testing.T) {
	e, ok := ParseLine(writeLine)
	if !ok {
		t.Fatal("write line should parse")
	}
	if len(e.Paths) != 1 || e.Paths[0] != "/etc/ld.so.preload" {
		t.Errorf("paths=%v", e.Paths)
	}
}

func TestParseSkipsBadLines(t *testing.T) {
	for _, bad := range []string{"", "   ", "not json", "{broken", "[1,2,3]", `{"unknown_event":{}}`} {
		if _, ok := ParseLine(bad); ok {
			t.Errorf("line %q should not parse", bad)
		}
	}
}

func TestParseStream(t *testing.T) {
	in := strings.Join([]string{execLine, "", "garbage", bpfLoadLine, writeLine}, "\n")
	events := ParseStream(strings.NewReader(in))
	if len(events) != 3 {
		t.Fatalf("want 3 events, got %d", len(events))
	}
	kinds := []string{events[0].Kind, events[1].Kind, events[2].Kind}
	want := []string{"exec", "kprobe", "kprobe"}
	for i := range want {
		if kinds[i] != want[i] {
			t.Errorf("event %d kind=%s want %s", i, kinds[i], want[i])
		}
	}
}
