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

func TestBufferDrain(t *testing.T) {
	b := NewBuffer(10)
	b.Add(report.Finding{Title: "a"}, report.Finding{Title: "b"})
	got := b.Drain()
	if len(got) != 2 || got[0].Title != "a" || got[1].Title != "b" {
		t.Fatalf("drain should return all pending findings: %+v", got)
	}
	if b.Len() != 0 {
		t.Errorf("drain should clear the buffer, len=%d", b.Len())
	}
	// Drain returns a copy: mutating it must not corrupt a later add.
	got[0].Title = "X"
	b.Add(report.Finding{Title: "c"})
	if next := b.Drain(); len(next) != 1 || next[0].Title != "c" {
		t.Errorf("buffer should be reusable after drain: %+v", next)
	}
	// Draining an empty buffer yields nothing.
	if empty := b.Drain(); len(empty) != 0 {
		t.Errorf("empty drain should be empty: %+v", empty)
	}
}

// A non-empty drain feeds an Append report (the run-mode delta-post contract):
// the collector accumulates these rather than treating them as a full posture.
func TestDrainYieldsAppendReport(t *testing.T) {
	b := NewBuffer(10)
	b.Add(report.Finding{Title: "crit", Severity: report.SeverityCritical})
	pending := b.Drain()
	rep := report.New("agent", "h", "", time.Now(), pending)
	rep.Append = true
	if !rep.Append {
		t.Fatal("run-mode delta report must be marked Append")
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Title != "crit" {
		t.Errorf("append report should carry the drained delta: %+v", rep.Findings)
	}
}

// Dropped counts findings the cap trimmed and resets on Drain, so run mode can
// warn (not silently lose) when a flush window overflows the buffer.
func TestBufferDroppedTracking(t *testing.T) {
	b := NewBuffer(3)
	for i := 0; i < 5; i++ {
		b.Add(report.Finding{Title: string(rune('a' + i))})
	}
	if b.Dropped() != 2 {
		t.Errorf("expected 2 dropped findings, got %d", b.Dropped())
	}
	b.Drain()
	if b.Dropped() != 0 {
		t.Errorf("drain should reset the dropped counter, got %d", b.Dropped())
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

// Tail must reset when the file is rotated by rename+recreate even if the new
// file already grew PAST the old offset (a size-only check misses this). We
// detect the inode change.
func TestTailDetectsInodeRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	// Old file already has content; Tail starts at its end (offset = size).
	if err := os.WriteFile(p, []byte("old line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Tail(ctx, p, 10*time.Millisecond, func(l string) { got <- l }) }()
	time.Sleep(120 * time.Millisecond) // let Tail capture initial offset+inode

	// Rotate the way logrotate does: rename the old file aside (its inode stays
	// allocated to the renamed file), then create a FRESH file at the path — which
	// therefore gets a NEW inode, the signal Tail keys on. os.Remove+recreate
	// instead would let the freed inode be REUSED on tmpfs/ext4, so the inode
	// never changes and rotation is undetectable by stat alone; the realistic
	// rename keeps this deterministic across filesystems. The new file is larger
	// than the old offset, so the size-shrink check alone would NOT catch it —
	// only the inode change does.
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("rotated line A\nrotated line B\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"rotated line A": true, "rotated line B": true}
	for i := 0; i < 2; i++ {
		select {
		case l := <-got:
			if !want[l] {
				t.Errorf("unexpected line %q (offset not reset on inode change?)", l)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("tail did not deliver lines from the rotated file")
		}
	}
}

// An unterminated line longer than maxLeftover must be dropped, not retained
// forever (it would grow leftover without bound → OOM). After the cap, Tail
// resyncs at the next newline and delivers the following complete line.
func TestTailCapsLeftover(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Tail(ctx, p, 10*time.Millisecond, func(l string) { got <- l }) }()
	time.Sleep(120 * time.Millisecond)

	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	// A huge unterminated partial line (no '\n'): must be dropped at the cap.
	_, _ = f.WriteString(strings.Repeat("X", maxLeftover+1024))
	_ = f.Close()
	time.Sleep(120 * time.Millisecond) // let Tail read+drop the oversized partial

	// Now a newline (ends the dropped garbage) plus a clean follow-up line.
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("\nclean line\n")
	_ = f.Close()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case l := <-got:
			if l == "clean line" {
				return // resynced past the dropped partial as intended
			}
			if len(l) > maxLeftover {
				t.Fatalf("the oversized partial line should have been dropped, got %d bytes", len(l))
			}
			// Tolerate an empty line (the residual of the dropped partial up to '\n').
		case <-deadline:
			t.Fatal("did not recover with a clean line after dropping the oversized partial")
		}
	}
}
