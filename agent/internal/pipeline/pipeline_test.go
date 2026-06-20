package pipeline

import (
	"context"
	"encoding/json"
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

// CorrelateReader drives the stream through ONE stateful correlator: a
// suspicious staging exec (exec_id X) followed by a connect (exec_id X) yields
// the base findings PLUS a single Critical realtime.correlated finding — the
// end-to-end exec→egress correlation the run/scan path relies on.
func TestCorrelateReaderExecThenConnect(t *testing.T) {
	const s = `{"process_exec":{"process":{"exec_id":"X","pid":1337,"binary":"/tmp/.x/payload","flags":"execve"},"parent":{"binary":"/bin/bash"}}}
{"process_kprobe":{"process":{"exec_id":"X","pid":1337,"binary":"/tmp/.x/payload"},"function_name":"tcp_connect","args":[{"sock_arg":{"daddr":"1.2.3.4","dport":443}}]}}`
	f := CorrelateReader(strings.NewReader(s), config.Defaults())
	var base, correlated int
	for _, x := range f {
		switch x.Check {
		case "realtime.exec":
			base++
		case "realtime.correlated":
			correlated++
			if x.Severity != report.SeverityCritical || x.Confidence != "high" {
				t.Errorf("correlated finding should be Critical/high: %+v", x)
			}
			if !strings.Contains(x.Detail, "1.2.3.4:443") {
				t.Errorf("correlated detail should name the dst: %q", x.Detail)
			}
		}
	}
	if base != 1 || correlated != 1 {
		t.Fatalf("want 1 base exec + 1 correlated finding, got base=%d correlated=%d: %+v", base, correlated, f)
	}
}

// A connect with no prior suspicious exec must NOT produce a correlated finding
// through the stateful reader (only the base findings, here none).
func TestCorrelateReaderNoSpuriousCorrelation(t *testing.T) {
	const s = `{"process_exec":{"process":{"exec_id":"Y","pid":5,"binary":"/usr/bin/curl"},"parent":{"binary":"/bin/bash"}}}
{"process_kprobe":{"process":{"exec_id":"Y","pid":5,"binary":"/usr/bin/curl"},"function_name":"tcp_connect","args":[{"sock_arg":{"daddr":"1.1.1.1","dport":443}}]}}`
	for _, f := range CorrelateReader(strings.NewReader(s), config.Defaults()) {
		if f.Check == "realtime.correlated" {
			t.Errorf("benign exec→connect must not correlate: %+v", f)
		}
	}
}

// The per-line Correlator (run mode's path) carries state across calls: feeding
// the suspicious exec then the connect on separate Line calls correlates, while
// a malformed line is nil.
func TestCorrelatorLineStateful(t *testing.T) {
	cw := NewCorrelator(config.Defaults())
	if got := cw.Line("garbage"); got != nil {
		t.Errorf("garbage line should yield nil, got %+v", got)
	}
	_ = cw.Line(`{"process_exec":{"process":{"exec_id":"X","pid":9,"binary":"/dev/shm/x","flags":"execve"},"parent":{"binary":"/bin/bash"}}}`)
	got := cw.Line(`{"process_kprobe":{"process":{"exec_id":"X","pid":9,"binary":"/dev/shm/x"},"function_name":"tcp_connect","args":[{"sock_arg":{"daddr":"2.3.4.5","dport":8080}}]}}`)
	var correlated bool
	for _, f := range got {
		if f.Check == "realtime.correlated" {
			correlated = true
		}
	}
	if !correlated {
		t.Errorf("stateful per-line correlator should correlate across calls: %+v", got)
	}
	if cw.Tracked() == 0 {
		t.Error("correlator should be tracking process state")
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

// readCheckpoint is a test helper that decodes the on-disk checkpoint.
func readCheckpoint(t *testing.T, path string) checkpoint {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var c checkpoint
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("unmarshal checkpoint: %v", err)
	}
	return c
}

// inodeOf returns a file's inode via the same helper Tail uses.
func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	return fileIno(fi)
}

// waitFor polls cond until it is true or the deadline elapses.
func waitFor(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// startTail runs TailWithState in a goroutine and returns the line channel plus a
// stop func that cancels AND WAITS for the goroutine to exit. Waiting matters for
// the checkpoint tests: TailWithState keeps writing tail.state(.tmp) into the
// temp dir, which races t.TempDir()'s RemoveAll cleanup if the goroutine outlives
// the test. The stop func is registered with t.Cleanup so every test drains it.
func startTail(t *testing.T, path, statePath string) chan string {
	t.Helper()
	got := make(chan string, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = TailWithState(ctx, path, statePath, 10*time.Millisecond, func(l string) {
			select {
			case got <- l:
			default: // never block the tailer if the test stops reading
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-done // ensure no more checkpoint writes before TempDir cleanup
	})
	return got
}

// TailWithState persists a checkpoint as the offset advances: after consuming a
// line, the state file records the file's inode and the byte offset.
func TestTailCheckpointWritten(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	state := filepath.Join(dir, "tail.state")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	got := startTail(t, p, state)
	time.Sleep(150 * time.Millisecond) // let Tail capture the initial offset

	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("event one\n")
	_ = f.Close()
	<-got

	if !waitFor(t, func() bool {
		c, ok := loadCheckpoint(state)
		return ok && c.Offset == int64(len("event one\n"))
	}) {
		t.Fatalf("checkpoint not advanced to the consumed offset: %+v", readCheckpoint(t, state))
	}
	if c := readCheckpoint(t, state); c.Inode != inodeOf(t, p) {
		t.Errorf("checkpoint inode %d != file inode %d", c.Inode, inodeOf(t, p))
	}
}

// On an inode MATCH, a fresh Tail RESUMES from the saved offset and catches up on
// events appended "during downtime" (between the first Tail stopping and the
// second starting), rather than jumping to EOF and skipping them.
func TestTailResumesOnInodeMatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	state := filepath.Join(dir, "tail.state")
	if err := os.WriteFile(p, []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Seed a checkpoint at the end of "before\n" with the CURRENT inode, simulating
	// a prior run that had consumed up to there.
	saveCheckpoint(state, checkpoint{Inode: inodeOf(t, p), Offset: int64(len("before\n"))})

	// Append the "downtime" events AFTER the checkpoint but BEFORE this Tail starts.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("during downtime A\nduring downtime B\n")
	_ = f.Close()

	got := startTail(t, p, state)

	want := map[string]bool{"during downtime A": true, "during downtime B": true}
	for i := 0; i < 2; i++ {
		select {
		case l := <-got:
			if !want[l] {
				t.Errorf("unexpected line %q (resumed from wrong offset?)", l)
			}
			if l == "before" {
				t.Error("resume should NOT re-read events before the checkpoint")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("resume did not deliver the downtime events")
		}
	}
}

// A line that straddles a restart must be REASSEMBLED, not dropped: the checkpoint
// records the offset at the START of the unconsumed partial line (its bytes live
// only in memory), so a fresh Tail re-reads it. Persisting the full offset (the
// bug) would skip "beta-par" and emit the corrupt fragment "tial".
func TestTailReassemblesPartialLineAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	state := filepath.Join(dir, "tail.state")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	// tailer #1: consume a full line, then read a PARTIAL line (no newline).
	got1 := make(chan string, 8)
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		_ = TailWithState(ctx1, p, state, 10*time.Millisecond, func(l string) { got1 <- l })
	}()
	time.Sleep(120 * time.Millisecond) // capture the initial (empty) offset
	appendStr(t, p, "alpha\n")
	if l := <-got1; l != "alpha" {
		cancel1()
		<-done1
		t.Fatalf("want alpha, got %q", l)
	}
	appendStr(t, p, "beta-par")        // partial: no trailing newline
	time.Sleep(150 * time.Millisecond) // let the tailer poll-read the partial
	if c, ok := loadCheckpoint(state); !ok || c.Offset != int64(len("alpha\n")) {
		cancel1()
		<-done1
		t.Fatalf("checkpoint must sit at the partial-line start %d, got %+v", len("alpha\n"), c)
	}
	cancel1()
	<-done1

	// downtime: complete the partial line; a fresh Tail must reassemble it.
	appendStr(t, p, "tial\n") // "beta-par" + "tial" = "beta-partial"
	got2 := startTail(t, p, state)
	select {
	case l := <-got2:
		if l != "beta-partial" {
			t.Errorf("partial line not reassembled across restart: got %q (want beta-partial)", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("resume did not deliver the reassembled line")
	}
}

func appendStr(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// On an inode MISMATCH (rotation into a different file), the stale offset is
// IGNORED and Tail starts at EOF — seeking the saved offset into a different file
// would read the wrong bytes. Only genuinely new appends are delivered.
func TestTailIgnoresStaleOffsetOnInodeMismatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	state := filepath.Join(dir, "tail.state")
	if err := os.WriteFile(p, []byte("fresh file contents already here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Checkpoint references a DIFFERENT inode than the current file — a rotation.
	saveCheckpoint(state, checkpoint{Inode: inodeOf(t, p) + 999999, Offset: 5})

	got := startTail(t, p, state)
	time.Sleep(150 * time.Millisecond) // start-at-EOF means the pre-existing line is NOT replayed

	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("brand new line\n")
	_ = f.Close()

	select {
	case l := <-got:
		if l != "brand new line" {
			t.Errorf("inode mismatch should start at EOF; got pre-existing/garbage line %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("did not deliver the new line after starting at EOF")
	}
	// The resolved checkpoint should now record the CURRENT inode, not the stale one.
	if c := readCheckpoint(t, state); c.Inode != inodeOf(t, p) {
		t.Errorf("checkpoint should be re-keyed to the current inode: %+v", c)
	}
}

// A missing or corrupt state file must be tolerated gracefully: Tail falls back
// to EOF and never crashes. (Equivalent to first-run behaviour.)
func TestTailToleratesMissingAndCorruptState(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	if err := os.WriteFile(p, []byte("preexisting\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Corrupt state file (not valid JSON) → loadCheckpoint returns ok=false.
	corrupt := filepath.Join(dir, "corrupt.state")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCheckpoint(corrupt); ok {
		t.Error("corrupt state should not be treated as a valid checkpoint")
	}
	// Missing state file → ok=false.
	if _, ok := loadCheckpoint(filepath.Join(dir, "does-not-exist.state")); ok {
		t.Error("missing state should not be treated as a valid checkpoint")
	}

	// Use the corrupt state file: Tail must fall back to EOF, not crash.
	got := startTail(t, p, corrupt)
	time.Sleep(150 * time.Millisecond) // let Tail capture the initial EOF offset

	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("after corrupt state\n")
	_ = f.Close()
	for {
		select {
		case l := <-got:
			// EOF start means "preexisting" is NOT replayed; only the new line.
			if l == "after corrupt state" {
				return
			}
			t.Errorf("should start at EOF after corrupt state; got %q", l)
		case <-time.After(3 * time.Second):
			t.Fatal("Tail stalled / crashed on a corrupt state file")
		}
	}
}

// Rotation (rename+recreate → new inode) must UPDATE the checkpoint to the new
// file's inode with the offset reset, so a later restart resumes the new file,
// not the rotated-away one.
func TestTailRotationUpdatesCheckpoint(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.log")
	state := filepath.Join(dir, "tail.state")
	if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldIno := inodeOf(t, p)

	got := startTail(t, p, state)
	time.Sleep(150 * time.Millisecond)

	// Rotate: rename old aside, create a fresh file (new inode).
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("rotated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	newIno := inodeOf(t, p)
	<-got // "rotated"

	if !waitFor(t, func() bool {
		c, ok := loadCheckpoint(state)
		return ok && c.Inode == newIno
	}) {
		t.Fatalf("checkpoint not updated to the rotated file's inode (old=%d new=%d): %+v",
			oldIno, newIno, readCheckpoint(t, state))
	}
}
