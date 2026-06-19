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
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func rank(s string) int {
	if r, ok := sevRank[s]; ok {
		return r
	}
	return 5
}

// Store is the concurrency-safe report store.
type Store struct {
	mu         sync.RWMutex
	reports    []Report
	path       string
	retain     time.Duration
	maxReports int
	now        func() time.Time
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
func (s *Store) AddReport(r Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Received.IsZero() {
		r.Received = s.now()
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

// latest returns the most recent report per (tool, host).
func (s *Store) latest() []Report {
	byKey := map[string]Report{}
	for _, r := range s.reports {
		k := r.Tool + "\x00" + r.Host
		if cur, ok := byKey[k]; !ok || reportTime(r).After(reportTime(cur)) {
			byKey[k] = r
		}
	}
	out := make([]Report, 0, len(byKey))
	for _, r := range byKey {
		out = append(out, r)
	}
	return out
}

// LatestFindings returns the current-posture findings (latest report per
// tool+host), flattened, filtered, and sorted worst-first.
func (s *Store) LatestFindings(f Filter) []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Finding
	for _, r := range s.latest() {
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
	for _, r := range s.latest() {
		if reportTime(r).After(updated) {
			updated = reportTime(r)
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
		sum.Tools = append(sum.Tools, ToolStatus{
			Tool: r.Tool, Host: r.Host, Worst: worstName(tWorst),
			Count: len(r.Findings), Clean: tWorst > 2, Time: r.Time,
		})
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
