package store

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// The correlation-layer fields (confidence, related) agentd emits must decode
// into store.Finding and survive the on-disk snapshot round trip, so the
// dashboard sees a correlated finding's confidence and lineage.
func TestFindingCorrelationFieldsRoundTrip(t *testing.T) {
	// Decode from the exact JSON shape agentd's report package marshals.
	const agentJSON = `{"check":"realtime.correlated","severity":"critical","title":"suspicious process then connected out","technique":"T1071","confidence":"high","related":["base: execution from a staging directory","dst=1.2.3.4:443"]}`
	var fd Finding
	if err := json.Unmarshal([]byte(agentJSON), &fd); err != nil {
		t.Fatalf("decode agent finding: %v", err)
	}
	if fd.Confidence != "high" || len(fd.Related) != 2 {
		t.Fatalf("decoded finding lost correlation fields: %+v", fd)
	}

	dir := t.TempDir()
	s, _ := New(dir, 0, 0)
	s.AddReport(Report{Tool: "agent", Host: "h", Time: time.Now(), Findings: []Finding{fd}})

	// Reopen from disk: the snapshot must preserve confidence + related.
	s2, _ := New(dir, 0, 0)
	got := s2.LatestFindings(Filter{})
	if len(got) != 1 {
		t.Fatalf("want 1 finding after reload, got %d", len(got))
	}
	if got[0].Confidence != "high" {
		t.Errorf("confidence lost across snapshot: %+v", got[0])
	}
	if len(got[0].Related) != 2 || got[0].Related[0] != "base: execution from a staging directory" {
		t.Errorf("related lost across snapshot: %+v", got[0].Related)
	}
}

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

// toolByName finds a ToolStatus in a Summary by tool name.
func toolByName(sum Summary, tool string) (ToolStatus, bool) {
	for _, ts := range sum.Tools {
		if ts.Tool == tool {
			return ts, true
		}
	}
	return ToolStatus{}, false
}

// Summary computes a per-tool last_seen + stale using the injected clock: a
// recently-received tool is NOT stale; one whose last receive is older than the
// threshold IS stale, with the right age.
func TestSummaryLastSeenAndStale(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 0)
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.staleAfter = 90 * time.Second

	// Fresh: received 10s ago → not stale.
	s.AddReport(Report{Tool: "agent", Host: "h", Received: now.Add(-10 * time.Second),
		Findings: []Finding{{Severity: "info"}}})
	// Stale: received 5m ago → stale.
	s.AddReport(Report{Tool: "stale-tool", Host: "h", Received: now.Add(-5 * time.Minute),
		Findings: []Finding{{Severity: "info"}}})

	sum := s.Summary()

	fresh, ok := toolByName(sum, "agent")
	if !ok {
		t.Fatal("agent tool missing from summary")
	}
	if fresh.Stale {
		t.Errorf("agent received 10s ago should NOT be stale: %+v", fresh)
	}
	if fresh.AgeSeconds != 10 {
		t.Errorf("agent age = %ds, want 10", fresh.AgeSeconds)
	}
	if !fresh.LastSeen.Equal(now.Add(-10 * time.Second)) {
		t.Errorf("agent last_seen = %v, want %v", fresh.LastSeen, now.Add(-10*time.Second))
	}

	stale, ok := toolByName(sum, "stale-tool")
	if !ok {
		t.Fatal("stale-tool missing from summary")
	}
	if !stale.Stale {
		t.Errorf("stale-tool received 5m ago should be stale: %+v", stale)
	}
	if stale.AgeSeconds != 300 {
		t.Errorf("stale-tool age = %ds, want 300", stale.AgeSeconds)
	}
}

// An empty heartbeat (Append report with zero findings) advances last_seen and
// keeps the tool fresh, while NOT adding to the finding set — distinguishing a
// quiet healthy agent from a dead one.
func TestSummaryHeartbeatKeepsFresh(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 0)
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.staleAfter = 90 * time.Second

	// An older append with one finding, then a recent EMPTY heartbeat.
	s.AddReport(Report{Tool: "agent", Host: "h", Received: now.Add(-5 * time.Minute), Append: true,
		Findings: []Finding{{Severity: "high", Title: "real finding"}}})
	s.AddReport(Report{Tool: "agent", Host: "h", Received: now.Add(-5 * time.Second), Append: true,
		Findings: []Finding{}}) // heartbeat: no new findings

	sum := s.Summary()
	ts, ok := toolByName(sum, "agent")
	if !ok {
		t.Fatal("agent missing")
	}
	if ts.Stale {
		t.Errorf("heartbeat 5s ago should keep the agent fresh: %+v", ts)
	}
	if ts.AgeSeconds != 5 {
		t.Errorf("age should reflect the heartbeat (5s), got %d", ts.AgeSeconds)
	}
	// The finding set is unchanged by the empty heartbeat.
	if ts.Count != 1 || sum.Findings != 1 {
		t.Errorf("empty heartbeat must not change the finding set: count=%d findings=%d", ts.Count, sum.Findings)
	}
}

// Empty heartbeats must COALESCE: posting many must not grow the report history
// (otherwise they flood /api/reports and evict real reports under maxReports) —
// at most one heartbeat per source is retained while liveness still advances.
func TestHeartbeatsCoalesceNoChurn(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 5000)
	base := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	s.AddReport(Report{Tool: "agent", Host: "h", Received: base, Append: true,
		Findings: []Finding{{Severity: "high", Title: "real"}}})
	before := len(s.Recent(100000))
	for i := 1; i <= 200; i++ {
		s.AddReport(Report{Tool: "agent", Host: "h", Received: base.Add(time.Duration(i) * time.Second), Append: true})
	}
	if grew := len(s.Recent(100000)) - before; grew > 1 {
		t.Errorf("200 heartbeats must coalesce: history grew by %d (want <=1)", grew)
	}
	if f := s.LatestFindings(Filter{}); len(f) != 1 || f[0].Title != "real" {
		t.Errorf("real finding lost to heartbeat churn: %+v", f)
	}
	// Liveness still advanced to the most recent heartbeat (base+200s).
	s.now = func() time.Time { return base.Add(205 * time.Second) }
	s.staleAfter = 90 * time.Second
	if ts, ok := toolByName(s.Summary(), "agent"); !ok || ts.Stale {
		t.Errorf("liveness should advance via the coalesced heartbeat: %+v", ts)
	}
}

// A clean agent's coalesced heartbeat (freshest Received, but pinned in place at
// its original slice index) must survive the COUNT cap when another tool floods
// the store with older reports — the cap drops genuinely-oldest by time, not by
// slice position. Otherwise a live clean agent silently vanishes from Summary.
func TestHeartbeatSurvivesCountCapFlood(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 3) // tiny count cap
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.staleAfter = 90 * time.Second
	// the agent posts ONLY a (recent) heartbeat — no findings report.
	s.AddReport(Report{Tool: "agent", Host: "h", Received: now.Add(-5 * time.Second), Append: true})
	// another tool floods with OLDER real reports, well past maxReports.
	for i := 0; i < 12; i++ {
		s.AddReport(Report{Tool: "busy", Host: "h", Time: now.Add(-time.Hour), Received: now.Add(-time.Hour),
			Findings: []Finding{{Severity: "low"}}})
	}
	ts, ok := toolByName(s.Summary(), "agent")
	if !ok {
		t.Fatal("clean agent vanished from Summary after a count-cap flood (heartbeat evicted by slice position)")
	}
	if ts.Stale {
		t.Errorf("agent heartbeat 5s ago should still be fresh: %+v", ts)
	}
}

// A tool with no recorded receive time is treated as stale (no evidence of life)
// with a sentinel age of -1.
func TestSummaryNeverSeenIsStale(t *testing.T) {
	s, _ := New(t.TempDir(), 0, 0)
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	// Report with a Time but a ZERO Received (never stamped) — drive current()'s
	// received tracker to stay zero.
	s.reports = append(s.reports, Report{Tool: "ghost", Host: "h", Time: now, Findings: []Finding{{Severity: "info"}}})
	sum := s.Summary()
	ts, ok := toolByName(sum, "ghost")
	if !ok {
		t.Fatal("ghost missing")
	}
	if !ts.Stale || ts.AgeSeconds != -1 {
		t.Errorf("never-seen tool should be stale with age -1: %+v", ts)
	}
}
