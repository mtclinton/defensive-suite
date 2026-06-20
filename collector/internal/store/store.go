// Package store keeps the findings the defensive-suite tools POST to the
// collector. It holds them in memory and persists an atomic JSON snapshot so the
// set survives a restart, with age/count retention. "Current posture" is the
// latest report per (tool, host); full history is available for the report feed.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Finding mirrors the shape every tool emits (see each tool's report package).
// Tool/Host/Time are filled by the collector when flattening for the API.
type Finding struct {
	Check     string    `json:"check"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	Path      string    `json:"path,omitempty"`
	Technique string    `json:"technique,omitempty"`
	Sigma     string    `json:"sigma,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	Host      string    `json:"host,omitempty"`
	Time      time.Time `json:"time,omitempty"`
}

// Report is one tool run's output, as POSTed to /ingest.
type Report struct {
	Tool     string          `json:"tool"`
	Host     string          `json:"host"`
	Time     time.Time       `json:"time"`
	Distro   string          `json:"distro,omitempty"`
	Findings []Finding       `json:"findings"`
	Summary  json.RawMessage `json:"summary,omitempty"`
	Received time.Time       `json:"received"`
	// Append marks an event-stream delta (e.g. agentd's `run` mode): instead of
	// replacing the prior posture for this (tool, host), the store accumulates
	// these findings onto a bounded rolling slice so deltas trimmed from the
	// agent's small buffer are retained here.
	Append bool `json:"append,omitempty"`
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func rank(s string) int {
	if r, ok := sevRank[s]; ok {
		return r
	}
	return 5
}

// DefaultStaleAfter is how long a (tool, host) may go without a received report
// before it is flagged stale. A healthy agentd heartbeats every flush (default
// ~10s), so 90s tolerates several missed flushes (transient slowness) before
// concluding the agent is dead or crash-looping.
const DefaultStaleAfter = 90 * time.Second

// Store is the concurrency-safe report store.
type Store struct {
	mu         sync.RWMutex
	reports    []Report
	path       string
	retain     time.Duration
	maxReports int
	now        func() time.Time
	// staleAfter is the liveness threshold for Summary's per-tool stale flag;
	// injectable (with now) for deterministic tests.
	staleAfter time.Duration
}

// New opens (and loads) a store rooted at dataDir.
func New(dataDir string, retain time.Duration, maxReports int) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	s := &Store{
		path:       filepath.Join(dataDir, "reports.json"),
		retain:     retain,
		maxReports: maxReports,
		now:        time.Now,
		staleAfter: DefaultStaleAfter,
	}
	s.load()
	return s, nil
}

func reportTime(r Report) time.Time {
	if !r.Received.IsZero() {
		return r.Received
	}
	return r.Time
}

// AddReport stores a report, stamping its receive time, and persists the set.
//
// An empty heartbeat (an Append report with no findings — agentd posts one every
// flush so liveness keeps advancing) must NOT accumulate as history: storing one
// every flush would flood /api/reports, evict real findings reports under
// maxReports, and rewrite the store to disk every flush. So we COALESCE it onto
// the prior heartbeat for this (tool,host) — at most one heartbeat per source,
// updated in place — and skip the disk save (a heartbeat is ephemeral; on restart
// the agent re-heartbeats within a flush interval). The agent still appears in
// Summary (its coalesced heartbeat carries the advancing Received), and real
// reports are untouched.
func (s *Store) AddReport(r Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Received.IsZero() {
		r.Received = s.now()
	}
	if r.Append && len(r.Findings) == 0 {
		for i := range s.reports {
			if s.reports[i].Tool == r.Tool && s.reports[i].Host == r.Host &&
				s.reports[i].Append && len(s.reports[i].Findings) == 0 {
				s.reports[i].Received = r.Received // advance liveness in place
				return
			}
		}
		s.reports = append(s.reports, r) // first heartbeat for this source
		return
	}
	s.reports = append(s.reports, r)
	s.prune()
	s.save()
}

func (s *Store) prune() {
	if s.retain > 0 {
		cutoff := s.now().Add(-s.retain)
		kept := make([]Report, 0, len(s.reports))
		for _, r := range s.reports {
			if reportTime(r).Before(cutoff) {
				continue
			}
			kept = append(kept, r)
		}
		s.reports = kept
	}
	if s.maxReports > 0 && len(s.reports) > s.maxReports {
		s.reports = append([]Report(nil), s.reports[len(s.reports)-s.maxReports:]...)
	}
}

func (s *Store) save() {
	data, err := json.MarshalIndent(s.reports, "", " ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o640) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var rs []Report
	if json.Unmarshal(data, &rs) == nil {
		s.reports = rs
		s.prune()
	}
}

// Filter narrows a findings query.
type Filter struct {
	Tool     string
	Severity string
	Host     string
}

// appendCap bounds the per-(tool, host) accumulated append-stream findings so a
// long-running event stream cannot grow the store without limit; the oldest
// findings are dropped once the cap is reached.
const appendCap = 2000

// posture is the current-posture report for one (tool, host) key after the
// accumulation pass: either the latest non-append report, or the rolling
// accumulation of append (event-stream delta) reports.
type posture struct {
	Tool     string
	Host     string
	Time     time.Time
	Findings []Finding
	// Received is the most recent receive time across the key's reports — the
	// liveness signal. A healthy agentd posts a heartbeat every flush even with
	// zero findings, so a Received that stops advancing means the agent is dead or
	// crash-looping, independent of how many findings it last reported.
	Received time.Time
}

// current resolves the current posture per (tool, host). For keys whose stream
// is append-mode (event deltas), it accumulates findings across all append
// reports into a bounded rolling slice. For normal keys it keeps the latest
// single report. If a key has both, the newest report wins per its kind: a
// later non-append (full) report replaces the accumulation; later append
// reports add to it.
func (s *Store) current() []posture {
	// Process reports in time order so accumulation and "latest wins" are stable.
	ordered := append([]Report(nil), s.reports...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return reportTime(ordered[i]).Before(reportTime(ordered[j]))
	})
	type acc struct {
		tool, host string
		time       time.Time
		received   time.Time
		findings   []Finding
	}
	byKey := map[string]*acc{}
	for _, r := range ordered {
		k := r.Tool + "\x00" + r.Host
		a := byKey[k]
		if a == nil {
			a = &acc{tool: r.Tool, host: r.Host}
			byKey[k] = a
		}
		rt := reportTime(r)
		if r.Append {
			// Event-stream delta: accumulate onto the current posture, bounded by
			// appendCap (oldest dropped) so a long stream cannot grow without limit.
			a.findings = append(a.findings, r.Findings...)
			if len(a.findings) > appendCap {
				a.findings = append([]Finding(nil), a.findings[len(a.findings)-appendCap:]...)
			}
		} else {
			// A full posture report replaces whatever came before.
			a.findings = append([]Finding(nil), r.Findings...)
		}
		if rt.After(a.time) {
			a.time = rt
		}
		// Track the latest receive time for liveness. An empty heartbeat (Append
		// with no findings) still advances this, so a quiet healthy agent stays
		// "fresh" while a dead one goes stale.
		if r.Received.After(a.received) {
			a.received = r.Received
		}
	}
	out := make([]posture, 0, len(byKey))
	for _, a := range byKey {
		out = append(out, posture{Tool: a.tool, Host: a.host, Time: a.time, Received: a.received, Findings: a.findings})
	}
	return out
}

// LatestFindings returns the current-posture findings (latest report per
// tool+host), flattened, filtered, and sorted worst-first.
func (s *Store) LatestFindings(f Filter) []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Finding
	for _, r := range s.current() {
		if f.Tool != "" && r.Tool != f.Tool {
			continue
		}
		if f.Host != "" && r.Host != f.Host {
			continue
		}
		for _, fd := range r.Findings {
			if f.Severity != "" && fd.Severity != f.Severity {
				continue
			}
			fd.Tool, fd.Host, fd.Time = r.Tool, r.Host, r.Time
			out = append(out, fd)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank(out[i].Severity) != rank(out[j].Severity) {
			return rank(out[i].Severity) < rank(out[j].Severity)
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// Recent returns up to limit most-recently-received reports, newest first.
func (s *Store) Recent(limit int) []Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs := append([]Report(nil), s.reports...)
	sort.SliceStable(rs, func(i, j int) bool { return reportTime(rs[i]).After(reportTime(rs[j])) })
	if limit > 0 && len(rs) > limit {
		rs = rs[:limit]
	}
	return rs
}

// ToolStatus is the latest posture of one tool on one host.
type ToolStatus struct {
	Tool  string    `json:"tool"`
	Host  string    `json:"host"`
	Worst string    `json:"worst"`
	Count int       `json:"count"`
	Clean bool      `json:"clean"`
	Time  time.Time `json:"time"`
	// LastSeen is when the collector last received a report (or heartbeat) for
	// this (tool, host); zero if never recorded. AgeSeconds is its age at the time
	// the summary was computed, and Stale is true when that age exceeds the store's
	// threshold — the signal a dead/crash-looping agent surfaces with.
	LastSeen   time.Time `json:"last_seen,omitempty"`
	AgeSeconds int64     `json:"age_seconds"`
	Stale      bool      `json:"stale"`
}

// Summary is the roll-up the dashboard header consumes.
type Summary struct {
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity"`
	Worst      string         `json:"worst"`
	Clean      bool           `json:"clean"`
	Tools      []ToolStatus   `json:"tools"`
	Hosts      []string       `json:"hosts"`
	Reports    int            `json:"reports"`
	Updated    time.Time      `json:"updated"`
}

func worstName(r int) string {
	for name, rr := range sevRank {
		if rr == r {
			return name
		}
	}
	return "info"
}

// Summary computes the current-posture roll-up.
func (s *Store) Summary() Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sum := Summary{BySeverity: map[string]int{}, Worst: "info", Clean: true, Reports: len(s.reports)}
	hosts := map[string]bool{}
	worst := 5
	var updated time.Time
	now := s.now()
	staleAfter := s.staleAfter
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	for _, r := range s.current() {
		if r.Time.After(updated) {
			updated = r.Time
		}
		if r.Host != "" {
			hosts[r.Host] = true
		}
		tWorst := 5
		for _, fd := range r.Findings {
			sum.Findings++
			sum.BySeverity[fd.Severity]++
			if rank(fd.Severity) < worst {
				worst = rank(fd.Severity)
			}
			if rank(fd.Severity) < tWorst {
				tWorst = rank(fd.Severity)
			}
		}
		// Liveness: age the last receive time against the clock. A never-seen key
		// (zero Received) is treated as stale — we have no evidence it is alive.
		ts := ToolStatus{
			Tool: r.Tool, Host: r.Host, Worst: worstName(tWorst),
			Count: len(r.Findings), Clean: tWorst > 2, Time: r.Time,
			LastSeen: r.Received,
		}
		if r.Received.IsZero() {
			ts.AgeSeconds = -1
			ts.Stale = true
		} else {
			age := now.Sub(r.Received)
			if age < 0 {
				age = 0
			}
			ts.AgeSeconds = int64(age / time.Second)
			ts.Stale = age > staleAfter
		}
		sum.Tools = append(sum.Tools, ts)
	}
	if sum.Findings > 0 {
		sum.Worst = worstName(worst)
	}
	sum.Clean = worst > 2
	for h := range hosts {
		sum.Hosts = append(sum.Hosts, h)
	}
	sort.Strings(sum.Hosts)
	sort.SliceStable(sum.Tools, func(i, j int) bool { return sum.Tools[i].Tool < sum.Tools[j].Tool })
	sum.Updated = updated
	return sum
}
