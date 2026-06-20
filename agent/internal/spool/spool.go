// Package spool is agentd's on-disk delivery buffer: when a flush's POST to the
// collector FAILS, the Report is written here instead of being dropped, and the
// next successful flush replays the backlog oldest-first. A routine collector
// restart (or any transient outage) therefore no longer silently destroys a
// flush window of findings — fail-silent is the worst failure mode for a
// detector. The spool is bounded (by count and bytes); when it overflows the
// OLDEST report is dropped with a LOUD stderr warning, never silently.
package spool

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PostFn re-delivers one spooled report. It returns nil on success (the file is
// then deleted) and a non-nil error on failure (replay stops, the file and every
// newer one are kept — order is preserved, collector is presumably still down).
type PostFn func(data []byte) error

// Defaults for the spool bounds. A flush window is small and flushes are ~10s
// apart, so 1000 reports buys a long outage while still bounding disk use; the
// byte cap is a backstop against an unusually large single report.
const (
	DefaultMaxReports = 1000
	DefaultMaxBytes   = 64 << 20 // 64 MiB
)

// Spool is an on-disk, ordered, bounded queue of report JSON. It is safe for use
// by a single flusher goroutine (agentd flushes serially from one ticker); it
// does not lock, matching that single-writer model.
type Spool struct {
	dir        string
	maxReports int
	maxBytes   int64
	seq        uint64
	// now and warn are injectable for tests; warn receives the loud "<4>" drop
	// warning (stderr in production).
	now  func() time.Time
	warn io.Writer
}

// New opens (creating if needed) a spool rooted at dir. maxReports/maxBytes <= 0
// fall back to the package defaults. The sequence counter is primed past any
// existing files so a restart keeps appending monotonically (never reusing a seq
// that would reorder a replay).
func New(dir string, maxReports int, maxBytes int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if maxReports <= 0 {
		maxReports = DefaultMaxReports
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	s := &Spool{
		dir:        dir,
		maxReports: maxReports,
		maxBytes:   maxBytes,
		now:        time.Now,
		warn:       os.Stderr,
	}
	// Prime the sequence past the highest existing file so new writes sort after
	// the backlog (oldest-first replay stays correct across restarts).
	for _, seq := range s.list() {
		if seq > s.seq {
			s.seq = seq
		}
	}
	return s, nil
}

// fileName is the on-disk name for a sequence number: zero-padded so lexical and
// numeric order agree, though list() parses the number to be safe regardless.
func fileName(seq uint64) string { return fmt.Sprintf("%020d.json", seq) }

// list returns the sequence numbers currently spooled, sorted oldest-first.
func (s *Spool) list() []uint64 {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var seqs []uint64
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(name, ".json"), 10, 64)
		if err != nil {
			continue
		}
		seqs = append(seqs, n)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs
}

// Write spools one report (its already-marshalled JSON) to the next monotonic
// sequence, then enforces the bound. data is written atomically (temp+rename) so
// a crash mid-write can't leave a partial file a later replay would choke on.
func (s *Spool) Write(data []byte) error {
	s.seq++
	name := fileName(s.seq)
	final := filepath.Join(s.dir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	s.enforceBound()
	return nil
}

// enforceBound drops the OLDEST spooled reports until both the count and byte
// caps are satisfied, emitting a LOUD "<4>" warning for each drop. Dropping the
// oldest (not the newest) preserves the most recent findings, which are the most
// actionable, and keeps replay order intact.
func (s *Spool) enforceBound() {
	seqs := s.list()
	// Count cap: drop oldest until within maxReports.
	for len(seqs) > s.maxReports {
		s.dropOldest(seqs[0], "count cap %d exceeded")
		seqs = seqs[1:]
	}
	// Byte cap: sum sizes, drop oldest until within maxBytes.
	var total int64
	sizes := make(map[uint64]int64, len(seqs))
	for _, seq := range seqs {
		if fi, err := os.Stat(filepath.Join(s.dir, fileName(seq))); err == nil {
			sizes[seq] = fi.Size()
			total += fi.Size()
		}
	}
	for total > s.maxBytes && len(seqs) > 0 {
		oldest := seqs[0]
		s.dropOldest(oldest, "byte cap exceeded")
		total -= sizes[oldest]
		seqs = seqs[1:]
	}
}

// dropOldest removes one spooled file and warns loudly (priority "<4>" = warning,
// the sd-daemon level journald reads). NEVER silent: a dropped finding the
// operator can't see is exactly the fail-silent mode this whole feature exists to
// prevent.
func (s *Spool) dropOldest(seq uint64, reasonFmt string) {
	_ = os.Remove(filepath.Join(s.dir, fileName(seq)))
	reason := fmt.Sprintf(reasonFmt, s.maxReports)
	fmt.Fprintf(s.warn, "<4>agent[spool] WARNING: dropped OLDEST spooled report %s (%s); collector outage longer than the spool can hold\n",
		fileName(seq), reason)
}

// Replay re-POSTs spooled reports OLDEST-FIRST via post. On success the file is
// deleted and replay continues; on the FIRST failure replay STOPS and the
// remaining (newer) reports are kept, preserving order — the collector is still
// down and we must not reorder newer ahead of older. Returns how many were
// replayed and the error that stopped it (nil if the whole backlog drained).
func (s *Spool) Replay(post PostFn) (int, error) {
	replayed := 0
	for _, seq := range s.list() {
		path := filepath.Join(s.dir, fileName(seq))
		data, err := os.ReadFile(path)
		if err != nil {
			// Unreadable spooled file: drop it (it can never be delivered) and warn,
			// rather than wedging replay forever on a corrupt entry.
			s.dropOldest(seq, "unreadable spool file (cap %d)")
			continue
		}
		if err := post(data); err != nil {
			return replayed, err // collector still down — keep this and all newer
		}
		_ = os.Remove(path)
		replayed++
	}
	return replayed, nil
}

// Len reports how many reports are currently spooled (pending re-delivery).
func (s *Spool) Len() int { return len(s.list()) }

// MarshalReport is a small convenience so callers can spool any JSON-marshalable
// report without importing encoding/json at the call site.
func MarshalReport(v any) ([]byte, error) { return json.Marshal(v) }
