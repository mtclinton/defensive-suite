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

// A real Tetragon process_exec export carries process.exec_id and
// parent.exec_id; the normalized Event must surface both so the correlator can
// key process lineage on them (not on reuse-prone pids).
const execIDLine = `{"process_exec":{"process":{"exec_id":"bGFi:111111:1337","pid":1337,"uid":0,"binary":"/tmp/.x/payload","arguments":"--beacon","cwd":"/tmp","flags":"execve rootcwd"},"parent":{"exec_id":"bGFi:1000:1000","pid":1000,"binary":"/bin/bash"}},"node_name":"lab","time":"2026-06-20T00:00:00Z"}`

func TestParseExecIDs(t *testing.T) {
	e, ok := ParseLine(execIDLine)
	if !ok {
		t.Fatal("exec line with exec_id should parse")
	}
	if e.ExecID != "bGFi:111111:1337" {
		t.Errorf("exec_id=%q (want bGFi:111111:1337)", e.ExecID)
	}
	if e.ParentExecID != "bGFi:1000:1000" {
		t.Errorf("parent exec_id=%q (want bGFi:1000:1000)", e.ParentExecID)
	}
}

// The ProtoJSON gRPC export uses camelCase keys (processExec / execId). The same
// parser must populate the normalized Event from that shape too.
const execIDCamelLine = `{"processExec":{"process":{"execId":"bGFi:222:55","pid":55,"binary":"/dev/shm/x"},"parent":{"execId":"bGFi:1:1","binary":"/bin/sh"}},"nodeName":"camel"}`

func TestParseExecCamelCase(t *testing.T) {
	e, ok := ParseLine(execIDCamelLine)
	if !ok {
		t.Fatal("camelCase exec line should parse")
	}
	if e.Kind != "exec" || e.ExecID != "bGFi:222:55" || e.ParentExecID != "bGFi:1:1" {
		t.Errorf("event=%+v", e)
	}
	if e.Binary != "/dev/shm/x" || e.Node != "camel" {
		t.Errorf("event=%+v", e)
	}
}

// A real tcp_connect process_kprobe export carries a sock_arg with the
// destination in daddr/dport. It must normalize to a "connect" Event carrying
// Dst/DstPort, plus the process exec_id for correlation.
const connectLine = `{"process_kprobe":{"process":{"exec_id":"bGFi:111111:1337","pid":1337,"binary":"/tmp/.x/payload"},"parent":{"exec_id":"bGFi:1000:1000","binary":"/bin/bash"},"function_name":"tcp_connect","policy_name":"dsuite-observe","args":[{"sock_arg":{"family":"AF_INET","type":"SOCK_STREAM","protocol":"IPPROTO_TCP","state":"TCP_SYN_SENT","saddr":"10.0.0.5","sport":40000,"daddr":"1.2.3.4","dport":443}}]},"node_name":"lab"}`

func TestParseConnect(t *testing.T) {
	e, ok := ParseLine(connectLine)
	if !ok {
		t.Fatal("tcp_connect line should parse")
	}
	if e.Kind != "connect" {
		t.Fatalf("kind=%q (want connect): %+v", e.Kind, e)
	}
	if e.Dst != "1.2.3.4" || e.DstPort != 443 {
		t.Errorf("dst=%s:%d (want 1.2.3.4:443)", e.Dst, e.DstPort)
	}
	if e.ExecID != "bGFi:111111:1337" || e.Function != "tcp_connect" {
		t.Errorf("event=%+v", e)
	}
	if e.Pid != 1337 || e.Binary != "/tmp/.x/payload" {
		t.Errorf("event=%+v", e)
	}
}

// The alternate sock-arg field names (destination_ip / destination_port) some
// policies/exports emit must also resolve to Dst/DstPort.
const connectAltLine = `{"process_kprobe":{"process":{"pid":42,"binary":"/usr/bin/curl"},"function_name":"security_socket_connect","args":[{"sock_arg":{"destination_ip":"8.8.8.8","destination_port":53}}]}}`

func TestParseConnectAltFields(t *testing.T) {
	e, ok := ParseLine(connectAltLine)
	if !ok {
		t.Fatal("alt connect line should parse")
	}
	if e.Kind != "connect" || e.Dst != "8.8.8.8" || e.DstPort != 53 {
		t.Errorf("event=%+v", e)
	}
}

// An egress kprobe whose sock arg has an unknown/empty shape must degrade
// gracefully: still a "connect" Event, just with no destination — never a crash
// or a dropped line.
const connectEmptyLine = `{"process_kprobe":{"process":{"pid":7,"binary":"/usr/bin/nc"},"function_name":"tcp_connect","args":[{"sock_arg":{}}]}}`

func TestParseConnectGracefulDegrade(t *testing.T) {
	e, ok := ParseLine(connectEmptyLine)
	if !ok {
		t.Fatal("empty-sock connect line should still parse")
	}
	if e.Kind != "connect" {
		t.Errorf("kind=%q (want connect)", e.Kind)
	}
	if e.Dst != "" || e.DstPort != 0 {
		t.Errorf("unknown sock shape should leave dst empty: %+v", e)
	}
	// A connect kprobe with no sock arg at all must also be fine.
	if e2, ok2 := ParseLine(`{"process_kprobe":{"process":{"pid":8},"function_name":"tcp_connect","args":[]}}`); !ok2 || e2.Kind != "connect" {
		t.Errorf("no-arg connect should parse as connect: %+v ok=%v", e2, ok2)
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

const writeMaskLine = `{"process_kprobe":{"process":{"pid":3,"binary":"/usr/sbin/sshd"},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/root/.ssh/authorized_keys"}},{"int_arg":4}]}}`

func TestParseKprobeIntMask(t *testing.T) {
	e, ok := ParseLine(writeMaskLine)
	if !ok {
		t.Fatal("masked write line should parse")
	}
	if len(e.Paths) != 1 || e.Paths[0] != "/root/.ssh/authorized_keys" {
		t.Errorf("paths=%v", e.Paths)
	}
	if !e.HasMask() {
		t.Fatal("event should carry an int mask")
	}
	if len(e.Ints) != 1 || e.Ints[0] != 4 {
		t.Errorf("ints=%v (want [4])", e.Ints)
	}
	if e.MayWrite() {
		t.Error("mask 4 (MAY_READ) must not register as a write")
	}
	// A write mask (2) flips MayWrite.
	w, _ := ParseLine(`{"process_kprobe":{"process":{"pid":3},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/etc/ld.so.preload"}},{"int_arg":2}]}}`)
	if !w.MayWrite() {
		t.Errorf("mask 2 (MAY_WRITE) should register as a write: ints=%v", w.Ints)
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

// An over-long first line (> maxLineBytes, e.g. an attacker-inflated argv) must
// be SKIPPED, not abort the stream: bufio.Scanner returned ErrTooLong and
// stopped, silently dropping everything after. ParseStream must keep going.
func TestParseStreamSkipsOverLongLine(t *testing.T) {
	huge := `{"process_exec":{"process":{"binary":"/x","arguments":"` +
		strings.Repeat("A", maxLineBytes+1024) + `"}}}`
	in := strings.Join([]string{huge, execLine, bpfLoadLine, writeLine}, "\n")
	events := ParseStream(strings.NewReader(in))
	if len(events) != 3 {
		t.Fatalf("over-long first line should be skipped, then 3 events parse; got %d", len(events))
	}
	if events[0].Kind != "exec" || events[1].Kind != "kprobe" || events[2].Kind != "kprobe" {
		t.Errorf("subsequent events lost: %+v", events)
	}
}

// A valid line longer than the internal buffer (but under the cap) must still
// parse — ReadSlice's ErrBufferFull is a continue, not a drop.
func TestParseStreamLongButValidLine(t *testing.T) {
	long := `{"process_exec":{"process":{"binary":"/tmp/x","flags":"execve","arguments":"` +
		strings.Repeat("B", 200*1024) + `"}}}`
	events := ParseStream(strings.NewReader(long + "\n" + bpfLoadLine + "\n"))
	if len(events) != 2 {
		t.Fatalf("a long-but-valid line should parse; got %d events", len(events))
	}
	if events[0].Kind != "exec" {
		t.Errorf("long valid line not parsed: %+v", events[0])
	}
}
