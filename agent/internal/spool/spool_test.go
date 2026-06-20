package spool

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// newTestSpool builds a spool with a captured warn writer so drop warnings are
// assertable.
func newTestSpool(t *testing.T, maxReports int, maxBytes int64) (*Spool, *bytes.Buffer) {
	t.Helper()
	s, err := New(t.TempDir(), maxReports, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	var warn bytes.Buffer
	s.warn = &warn
	return s, &warn
}

// A failed POST persists the report: after Write the file is present in the
// spool dir and counts toward Len.
func TestWriteSpoolsReport(t *testing.T) {
	s, _ := newTestSpool(t, 0, 0)
	if err := s.Write([]byte(`{"tool":"agent","findings":[]}`)); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("expected 1 spooled report, got %d", s.Len())
	}
	if len(s.list()) != 1 {
		t.Errorf("spool file should be on disk: %v", s.list())
	}
}

// The next flush with a working post replays the backlog and DELETES the files.
func TestReplayDeletesOnSuccess(t *testing.T) {
	s, _ := newTestSpool(t, 0, 0)
	for i := 0; i < 3; i++ {
		if err := s.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	n, err := s.Replay(func(data []byte) error {
		seen = append(seen, string(data))
		return nil
	})
	if err != nil {
		t.Fatalf("replay error: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 replayed, got %d", n)
	}
	if s.Len() != 0 {
		t.Errorf("successful replay should empty the spool, got %d", s.Len())
	}
	// Oldest-first order.
	want := []string{`{"n":0}`, `{"n":1}`, `{"n":2}`}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Errorf("replay order = %v, want oldest-first %v", seen, want)
	}
}

// Replay stops on the FIRST failure and keeps the remaining (newer) reports;
// order is preserved across a later successful replay.
func TestReplayStopsOnFirstFailureOrderPreserved(t *testing.T) {
	s, _ := newTestSpool(t, 0, 0)
	for i := 0; i < 4; i++ {
		if err := s.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	// Fail after delivering the first two.
	var delivered []string
	failAfter := 2
	count := 0
	n, err := s.Replay(func(data []byte) error {
		if count >= failAfter {
			return errors.New("collector down")
		}
		count++
		delivered = append(delivered, string(data))
		return nil
	})
	if err == nil {
		t.Fatal("replay should surface the failure")
	}
	if n != 2 {
		t.Errorf("only the first two should have been delivered, got %d", n)
	}
	if s.Len() != 2 {
		t.Errorf("the two newer reports must be kept, got %d remaining", s.Len())
	}
	if strings.Join(delivered, ",") != `{"n":0},{"n":1}` {
		t.Errorf("delivered out of order: %v", delivered)
	}
	// A later successful replay delivers the remaining two, still oldest-first.
	var rest []string
	n2, err := s.Replay(func(data []byte) error { rest = append(rest, string(data)); return nil })
	if err != nil || n2 != 2 {
		t.Fatalf("second replay n=%d err=%v", n2, err)
	}
	if strings.Join(rest, ",") != `{"n":2},{"n":3}` {
		t.Errorf("remaining replay out of order: %v", rest)
	}
	if s.Len() != 0 {
		t.Errorf("spool should be empty after full drain, got %d", s.Len())
	}
}

// Exceeding the COUNT cap drops the OLDEST report and emits a loud "<4>" warning.
func TestCountCapDropsOldestWithWarning(t *testing.T) {
	s, warn := newTestSpool(t, 2, 0) // cap at 2 reports
	for i := 0; i < 3; i++ {
		if err := s.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	if s.Len() != 2 {
		t.Fatalf("count cap should hold at 2, got %d", s.Len())
	}
	if !strings.Contains(warn.String(), "<4>") || !strings.Contains(strings.ToLower(warn.String()), "dropped") {
		t.Errorf("a loud <4> drop warning must be emitted, got: %q", warn.String())
	}
	// The OLDEST (n:0) was the one dropped: a replay should see n:1 then n:2.
	var seen []string
	_, _ = s.Replay(func(data []byte) error { seen = append(seen, string(data)); return nil })
	if strings.Join(seen, ",") != `{"n":1},{"n":2}` {
		t.Errorf("oldest should have been dropped, surviving=%v", seen)
	}
}

// Exceeding the BYTE cap drops the oldest until within budget, loudly.
func TestByteCapDropsOldestWithWarning(t *testing.T) {
	// Each report ~10 bytes; cap at 25 bytes → keeps ~2.
	s, warn := newTestSpool(t, 0, 25)
	payload := func(i int) []byte { return []byte(fmt.Sprintf("0123456%03d", i)) } // 10 bytes each
	for i := 0; i < 4; i++ {
		if err := s.Write(payload(i)); err != nil {
			t.Fatal(err)
		}
	}
	// 4 * 10 = 40 bytes > 25 → at most 2 survive.
	if s.Len() > 2 {
		t.Errorf("byte cap should keep at most 2 reports, got %d", s.Len())
	}
	if !strings.Contains(warn.String(), "<4>") {
		t.Errorf("byte-cap drop must warn loudly: %q", warn.String())
	}
}

// A restart re-opens the same dir and keeps appending past the existing backlog
// so replay order stays correct (no seq reuse that would reorder).
func TestReopenPreservesOrder(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = s1.Write([]byte(`{"n":0}`))
	_ = s1.Write([]byte(`{"n":1}`))

	s2, err := New(dir, 0, 0) // "restart"
	if err != nil {
		t.Fatal(err)
	}
	_ = s2.Write([]byte(`{"n":2}`))

	var seen []string
	if _, err := s2.Replay(func(data []byte) error { seen = append(seen, string(data)); return nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != `{"n":0},{"n":1},{"n":2}` {
		t.Errorf("order not preserved across reopen: %v", seen)
	}
}

// An unreadable spool entry is dropped (with a warning) so a corrupt file can't
// wedge replay forever; the next good report still delivers.
func TestReplaySkipsUnreadableEntry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 is still readable, can't simulate an unreadable file")
	}
	s, warn := newTestSpool(t, 0, 0)
	_ = s.Write([]byte(`{"n":0}`))
	_ = s.Write([]byte(`{"n":1}`))
	// Make the FIRST (oldest) entry unreadable: ReadFile then fails with EACCES so
	// Replay drops it and continues to the good entry.
	first := s.list()[0]
	path := s.dir + string(os.PathSeparator) + fileName(first)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0o600) // so t.TempDir() cleanup can remove it

	var seen []string
	_, err := s.Replay(func(data []byte) error { seen = append(seen, string(data)); return nil })
	if err != nil {
		t.Fatalf("replay should not error on an unreadable entry it drops: %v", err)
	}
	if strings.Join(seen, ",") != `{"n":1}` {
		t.Errorf("the good report should still deliver, got %v", seen)
	}
	if !strings.Contains(warn.String(), "<4>") {
		t.Errorf("dropping an unreadable entry should warn: %q", warn.String())
	}
}

// MarshalReport is a thin convenience over encoding/json — round-trips a struct.
func TestMarshalReport(t *testing.T) {
	data, err := MarshalReport(map[string]int{"a": 1})
	if err != nil || string(data) != `{"a":1}` {
		t.Errorf("MarshalReport = %q, %v", data, err)
	}
}
