package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/config"
	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

const stream = `{"process_exec":{"process":{"pid":1337,"binary":"/tmp/.x/payload","flags":"execve"},"parent":{"binary":"/bin/bash"}}}
{"process_kprobe":{"process":{"pid":2,"binary":"/usr/bin/evil"},"function_name":"security_bpf_prog_load","args":[]}}
{"process_kprobe":{"process":{"pid":3,"binary":"/usr/bin/tee"},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/etc/ld.so.preload"}}]}}
{"process_exec":{"process":{"pid":9,"binary":"/usr/bin/ls"},"parent":{"binary":"/bin/bash"}}}`

func TestProcessReader(t *testing.T) {
	f := ProcessReader(strings.NewReader(stream), config.Defaults())
	if len(f) != 3 {
		t.Fatalf("want 3 findings (staging exec, bpf load, ld.so.preload write), got %d: %+v", len(f), f)
	}
	sev := map[report.Severity]int{}
	for _, x := range f {
		sev[x.Severity]++
	}
	if sev[report.SeverityMedium] != 1 || sev[report.SeverityHigh] != 1 || sev[report.SeverityCritical] != 1 {
		t.Errorf("severities=%v", sev)
	}
}

func TestEvalLine(t *testing.T) {
	f := EvalLine(`{"process_exec":{"process":{"binary":"/dev/shm/x"}}}`, config.Defaults())
	if len(f) != 1 || f[0].Severity != report.SeverityMedium {
		t.Errorf("findings=%+v", f)
	}
	if got := EvalLine("garbage", config.Defaults()); got != nil {
		t.Errorf("garbage should yield nil, got %+v", got)
	}
}

func TestBuffer(t *testing.T) {
	b := NewBuffer(3)
	for i := 0; i < 5; i++ {
		b.Add(report.Finding{Title: string(rune('a' + i))})
	}
	if b.Len() != 3 {
		t.Errorf("cap not enforced: len=%d", b.Len())
	}
	snap := b.Snapshot()
	if len(snap) != 3 || snap[0].Title != "c" || snap[2].Title != "e" {
		t.Errorf("snapshot=%+v (want oldest trimmed)", snap)
	}
	// Snapshot is a copy — mutating it must not affect the buffer.
	snap[0].Title = "X"
	if b.Snapshot()[0].Title != "c" {
		t.Error("snapshot should be an independent copy")
	}
}

func TestTailFollowsAppends(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Tail(ctx, p, 10*time.Millisecond, func(l string) { got <- l }) }()

	// Tail starts at end-of-file (only new events), so the append must happen
	// after Tail has captured the initial empty offset — give it a few poll cycles.
	time.Sleep(150 * time.Millisecond)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("line one\nline two\n")
	_ = f.Close()

	for i := 0; i < 2; i++ {
		select {
		case l := <-got:
			if !strings.HasPrefix(l, "line ") {
				t.Errorf("unexpected line %q", l)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("tail did not deliver appended lines")
		}
	}
}
