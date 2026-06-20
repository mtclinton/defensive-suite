package store

import (
	"fmt"
	"testing"
	"time"
)

func TestLatestPerToolHost(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 0)
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	s.AddReport(Report{Tool: "a", Host: "h", Time: t1, Received: t1, Findings: []Finding{{Severity: "low", Title: "old"}}})
	s.AddReport(Report{Tool: "a", Host: "h", Time: t2, Received: t2, Findings: []Finding{{Severity: "critical", Title: "new"}}})
	f := s.LatestFindings(Filter{})
	if len(f) != 1 || f[0].Title != "new" {
		t.Errorf("expected only the latest report's findings, got %+v", f)
	}
	if f[0].Tool != "a" || f[0].Host != "h" {
		t.Errorf("findings should be annotated with tool/host: %+v", f[0])
	}
}

func TestLatestFindingsSortAndFilter(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 0)
	s.AddReport(Report{Tool: "a", Host: "h", Findings: []Finding{{Severity: "low"}, {Severity: "critical"}}})
	s.AddReport(Report{Tool: "b", Host: "h", Findings: []Finding{{Severity: "high"}}})
	all := s.LatestFindings(Filter{})
	if len(all) != 3 || all[0].Severity != "critical" {
		t.Errorf("worst-first sort wrong: %+v", all)
	}
	if got := s.LatestFindings(Filter{Tool: "b"}); len(got) != 1 || got[0].Severity != "high" {
		t.Errorf("tool filter: %+v", got)
	}
	if got := s.LatestFindings(Filter{Severity: "critical"}); len(got) != 1 {
		t.Errorf("severity filter: %+v", got)
	}
}

func TestRetentionByAge(t *testing.T) {
	s, _ := New(t.TempDir(), 24*time.Hour, 0)
	base := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	s.AddReport(Report{Tool: "old", Host: "h", Received: base.Add(-48 * time.Hour), Findings: []Finding{{Severity: "high"}}})
	s.AddReport(Report{Tool: "new", Host: "h", Received: base, Findings: []Finding{{Severity: "low"}}})
	if got := len(s.Recent(0)); got != 1 {
		t.Errorf("age retention: got %d reports, want 1", got)
	}
}

func TestRetentionByCount(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 2)
	for i := 0; i < 5; i++ {
		s.AddReport(Report{Tool: fmt.Sprintf("t%d", i), Host: "h", Findings: []Finding{{Severity: "info"}}})
	}
	if got := len(s.Recent(0)); got != 2 {
		t.Errorf("count retention: got %d reports, want 2", got)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir, 0, 0)
	s.AddReport(Report{Tool: "authwatch", Host: "h", Findings: []Finding{{Severity: "critical", Title: "unowned PAM module"}}})
	s2, err := New(dir, 0, 0) // reads the snapshot written by s
	if err != nil {
		t.Fatal(err)
	}
	f := s2.LatestFindings(Filter{})
	if len(f) != 1 || f[0].Title != "unowned PAM module" {
		t.Errorf("snapshot did not round-trip: %+v", f)
	}
}

func TestSummary(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 0)
	s.AddReport(Report{Tool: "a", Host: "h1", Findings: []Finding{{Severity: "critical"}, {Severity: "info"}}})
	s.AddReport(Report{Tool: "b", Host: "h2", Findings: []Finding{{Severity: "low"}}})
	sum := s.Summary()
	if sum.Findings != 3 || sum.Worst != "critical" || sum.Clean {
		t.Errorf("summary=%+v", sum)
	}
	if sum.BySeverity["critical"] != 1 || sum.BySeverity["info"] != 1 {
		t.Errorf("by_severity=%v", sum.BySeverity)
	}
	if len(sum.Hosts) != 2 || len(sum.Tools) != 2 {
		t.Errorf("hosts=%v tools=%v", sum.Hosts, sum.Tools)
	}
}

func TestSummaryCleanWhenNoMediumPlus(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 0)
	s.AddReport(Report{Tool: "a", Host: "h", Findings: []Finding{{Severity: "low"}, {Severity: "info"}}})
	if sum := s.Summary(); !sum.Clean || sum.Worst != "low" {
		t.Errorf("low/info only should be clean: %+v", sum)
	}
}

// Two Append reports for the same (tool, host) must ACCUMULATE, not replace —
// otherwise agentd's event-stream deltas trimmed from its small buffer are lost.
func TestAppendReportsAccumulate(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 0)
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)
	s.AddReport(Report{Tool: "agent", Host: "h", Time: t1, Received: t1, Append: true,
		Findings: []Finding{{Severity: "critical", Title: "first"}}})
	s.AddReport(Report{Tool: "agent", Host: "h", Time: t2, Received: t2, Append: true,
		Findings: []Finding{{Severity: "high", Title: "second"}}})
	f := s.LatestFindings(Filter{})
	if len(f) != 2 {
		t.Fatalf("append reports should accumulate to 2 findings, got %d: %+v", len(f), f)
	}
	titles := map[string]bool{f[0].Title: true, f[1].Title: true}
	if !titles["first"] || !titles["second"] {
		t.Errorf("both append deltas should survive: %+v", f)
	}
	if sum := s.Summary(); sum.Findings != 2 {
		t.Errorf("summary should reflect accumulated findings: %+v", sum)
	}
}

// A non-append (full posture) report REPLACES the prior posture, including any
// earlier accumulation; later appends accumulate onto the new baseline.
func TestNonAppendReplacesThenAppendsAccumulate(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 0)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Accumulate two append deltas.
	s.AddReport(Report{Tool: "agent", Host: "h", Time: base, Received: base, Append: true,
		Findings: []Finding{{Severity: "high", Title: "delta1"}}})
	s.AddReport(Report{Tool: "agent", Host: "h", Time: base.Add(time.Minute), Received: base.Add(time.Minute), Append: true,
		Findings: []Finding{{Severity: "high", Title: "delta2"}}})
	// A full report replaces them.
	s.AddReport(Report{Tool: "agent", Host: "h", Time: base.Add(2 * time.Minute), Received: base.Add(2 * time.Minute),
		Findings: []Finding{{Severity: "critical", Title: "full"}}})
	f := s.LatestFindings(Filter{})
	if len(f) != 1 || f[0].Title != "full" {
		t.Fatalf("full report should replace accumulation, got %+v", f)
	}
	// A later append accumulates onto the replaced baseline.
	s.AddReport(Report{Tool: "agent", Host: "h", Time: base.Add(3 * time.Minute), Received: base.Add(3 * time.Minute), Append: true,
		Findings: []Finding{{Severity: "low", Title: "delta3"}}})
	f = s.LatestFindings(Filter{})
	if len(f) != 2 {
		t.Fatalf("append after full should accumulate onto baseline, got %d: %+v", len(f), f)
	}
}
