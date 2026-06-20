// Package correlate is agentd's stateful correlation layer. It turns single
// events the stateless rules engine scores in isolation into lineage-aware,
// high-fidelity findings.
//
// The integration point is Correlator.Process: it runs the base (stateless)
// rules on every event AND maintains bounded, TTL'd per-process state so that
//
//	(A) a "connect" event from a process whose exec was flagged suspicious
//	    (staging-dir / fileless exec, or a bpf load) is escalated to a single
//	    Critical "suspicious process then connected out" C2 finding (T1071 /
//	    T1041), and
//
//	(B) every base finding is annotated with its process ANCESTRY ("spawned by
//	    curl ← bash ← sshd"), escalating confidence when an ancestor was itself
//	    flagged suspicious.
//
// State is keyed by Tetragon's exec_id (stable across pid reuse), bounded to a
// fixed number of processes with a TTL, and evicted oldest/expired-first so the
// map can never grow without bound under `run` mode's forever-stream. The clock
// is injected so TTL behaviour is deterministic in tests.
package correlate

import (
	"fmt"
	"strings"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
	"github.com/mtclinton/defensive-suite/agent/internal/rules"
	"github.com/mtclinton/defensive-suite/agent/internal/tetragon"
)

// Defaults bound the state so the correlator is safe to run forever.
const (
	// DefaultMaxProcs caps how many exec_ids we track. Beyond this the oldest
	// (by first-seen) entry is evicted before a new one is admitted.
	DefaultMaxProcs = 4096
	// DefaultTTL is how long a process's correlation state lives after it is
	// first seen. An exec older than this no longer arms a connect correlation
	// and is eligible for eviction.
	DefaultTTL = 10 * time.Minute
	// maxLineageDepth bounds the parent-chain walk so a (malicious or buggy)
	// cyclic/very-deep exec_id chain cannot loop or blow the stack.
	maxLineageDepth = 16
	// maxSuspicionsPerProc caps the per-process suspicion set. realtime.bpf
	// (security_bpf_prog_load) fires repeatedly under ONE exec_id, so a loader
	// looping eBPF loads would otherwise append one suspicion per load for the
	// whole TTL → unbounded growth → OOM. Correlation only needs presence +
	// suspicious[0] + the first exfilish entry, so a small cap (with dedup) loses
	// zero fidelity.
	maxSuspicionsPerProc = 16
	// maxCorrelatedDsts caps the per-process set of already-correlated
	// destinations used to suppress duplicate correlated findings from a beaconing
	// implant. Bounded so it can't grow without limit under a fast beacon.
	maxCorrelatedDsts = 64
)

// procState is the per-process correlation state for one exec_id.
type procState struct {
	execID       string
	parentExecID string
	binary       string
	firstSeen    time.Time
	// lastSeen is refreshed on every event for this exec_id. Eviction/TTL ages
	// off lastSeen (not firstSeen) so a process that stays ACTIVE for >TTL and
	// then beacons is still armed; firstSeen is kept for info/ordering.
	lastSeen time.Time
	// suspicious is the set of base findings on THIS process that arm an egress
	// correlation (staging/fileless exec, bpf load). Bounded + deduped (see
	// maxSuspicionsPerProc): a looping bpf loader cannot grow it without bound.
	suspicious []suspicion
	// correlatedDsts is the bounded set of destinations already escalated for
	// this process, used to suppress duplicate correlated findings from a
	// beaconing implant (see maxCorrelatedDsts).
	correlatedDsts map[string]bool
}

// suspicion records why a process is flagged, for the correlated finding's
// detail/technique and the lineage escalation.
type suspicion struct {
	reason    string // human reason, e.g. "execution from a staging directory"
	technique string // base technique, e.g. "T1059"
	exfilish  bool   // base looks exfil-oriented → prefer T1041 over T1071
}

// addSuspicion records susp on the process, deduping equal suspicions and
// capping the slice at maxSuspicionsPerProc. A repeating arming finding (e.g. a
// loader looping security_bpf_prog_load under one exec_id) therefore cannot grow
// the slice without bound. Correlation only needs presence + suspicious[0] + the
// first exfilish entry, so dedup+cap loses zero fidelity.
func (st *procState) addSuspicion(susp suspicion) {
	for _, s := range st.suspicious {
		if s == susp {
			return // already recorded an equal suspicion
		}
	}
	if len(st.suspicious) >= maxSuspicionsPerProc {
		return // bounded: further distinct suspicions are dropped
	}
	st.suspicious = append(st.suspicious, susp)
}

// Correlator is the stateful, bounded correlation engine. It is NOT safe for
// concurrent use; agentd drives it from a single tail goroutine.
type Correlator struct {
	byExec map[string]*procState
	// pidIndex maps the most recent pid → exec_id, so a "connect" event that
	// (in some export shapes) lacks an exec_id can still be attributed to the
	// process that most recently exec'd under that pid.
	pidIndex map[uint32]string
	maxProcs int
	ttl      time.Duration
	now      func() time.Time
}

// New builds a Correlator with the given bounds and an injected clock. A nil
// clock defaults to time.Now; non-positive bounds fall back to the defaults.
func New(maxProcs int, ttl time.Duration, now func() time.Time) *Correlator {
	if maxProcs <= 0 {
		maxProcs = DefaultMaxProcs
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Correlator{
		byExec:   make(map[string]*procState),
		pidIndex: make(map[uint32]string),
		maxProcs: maxProcs,
		ttl:      ttl,
		now:      now,
	}
}

// Tracked reports how many processes are currently held in state (for tests /
// bound assertions).
func (c *Correlator) Tracked() int { return len(c.byExec) }

// Process is the integration point: it returns the base findings for ev (via
// rules.Eval) PLUS any correlated findings, while updating correlation state.
// It is deterministic given the injected clock.
func (c *Correlator) Process(ev tetragon.Event, cfg rules.Config) []report.Finding {
	c.evictExpired()

	// Record/refresh lineage state for any event that identifies a process, so a
	// later connect can be attributed even if its own exec wasn't suspicious.
	c.track(ev)

	base := rules.Eval(ev, cfg)
	base = c.annotateAndArm(ev, base)

	out := base
	if ev.Kind == "connect" {
		if cf, ok := c.correlateEgress(ev); ok {
			out = append(out, cf)
		}
	}
	return out
}

// track upserts the per-process state for ev's process (exec/connect/kprobe all
// carry an exec_id) and maintains the pid→exec_id index.
func (c *Correlator) track(ev tetragon.Event) {
	if ev.ExecID == "" {
		// No exec_id: there is no stable key, so the process can't be tracked or
		// pid-indexed and correlation is skipped for this event. (Tetragon exec /
		// kprobe events virtually always carry an exec_id, so this is rare.)
		return
	}
	st := c.byExec[ev.ExecID]
	now := c.now()
	if st == nil {
		c.admit()
		st = &procState{
			execID:    ev.ExecID,
			firstSeen: now,
		}
		c.byExec[ev.ExecID] = st
	}
	st.lastSeen = now // age eviction/TTL off the most recent activity
	if ev.ParentExecID != "" {
		st.parentExecID = ev.ParentExecID
	}
	if ev.Binary != "" {
		st.binary = ev.Binary
	}
	if ev.Kind == "exit" {
		// On exit the pid no longer belongs to this process. Drop a pid-index
		// entry that still points here so a later no-exec_id connect on that pid
		// (before reuse) is NOT misattributed to this now-dead process. (Do this
		// instead of re-indexing the pid below.)
		if ev.Pid != 0 && c.pidIndex[ev.Pid] == ev.ExecID {
			delete(c.pidIndex, ev.Pid)
		}
		return
	}
	if ev.Pid != 0 {
		c.pidIndex[ev.Pid] = ev.ExecID
	}
}

// admit makes room for one new process if we are at the cap, evicting the
// oldest-by-last-seen (least recently active) entry so the map stays bounded.
// Ties on lastSeen are broken deterministically by execID (Go map iteration
// order is non-deterministic), so eviction is reproducible.
func (c *Correlator) admit() {
	if len(c.byExec) < c.maxProcs {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, st := range c.byExec {
		switch {
		case oldestKey == "":
		case st.lastSeen.Before(oldest):
		case st.lastSeen.Equal(oldest) && k < oldestKey:
			// deterministic tie-break
		default:
			continue
		}
		oldestKey, oldest = k, st.lastSeen
	}
	if oldestKey != "" {
		c.forget(oldestKey)
	}
}

// evictExpired drops every process idle past the TTL (aged off lastSeen, not
// firstSeen, so an actively-emitting process stays armed), and prunes any
// pid-index entries that pointed at them. Residual limit: a process that is
// SILENT between its suspicious exec and a beacon arriving >TTL later is still
// evicted before the beacon and won't correlate — inherent to a bounded window.
func (c *Correlator) evictExpired() {
	cutoff := c.now().Add(-c.ttl)
	for k, st := range c.byExec {
		if st.lastSeen.Before(cutoff) {
			c.forget(k)
		}
	}
}

// forget removes a process from state and clears any pid-index entries pointing
// at it, so an evicted process cannot be resurrected via a stale pid mapping.
func (c *Correlator) forget(execID string) {
	delete(c.byExec, execID)
	for pid, ex := range c.pidIndex {
		if ex == execID {
			delete(c.pidIndex, pid)
		}
	}
}

// annotateAndArm records suspicious base findings onto the process state (so a
// later connect can correlate) and annotates EVERY base finding with the
// process lineage. It returns the (lineage-annotated) base findings.
func (c *Correlator) annotateAndArm(ev tetragon.Event, base []report.Finding) []report.Finding {
	st := c.byExec[ev.ExecID]
	for i := range base {
		f := &base[i]
		if susp, ok := suspicionFor(*f); ok && st != nil {
			st.addSuspicion(susp)
		}
		// Lineage: attach the ancestry to every base finding. If an ancestor was
		// itself flagged suspicious, escalate confidence.
		if st != nil {
			lineage, ancestorFlagged := c.lineage(st)
			if len(lineage) > 1 { // more than just this process
				f.Related = append(f.Related, "lineage: "+strings.Join(lineage, " ← "))
			}
			if f.Confidence == "" {
				f.Confidence = baseConfidence(*f)
			}
			if ancestorFlagged {
				f.Confidence = bumpConfidence(f.Confidence)
				f.Related = append(f.Related, "ancestor previously flagged suspicious")
			}
		} else if f.Confidence == "" {
			f.Confidence = baseConfidence(*f)
		}
	}
	return base
}

// correlateEgress is Correlation A: when a connect arrives for a process (by
// exec_id, or by pid fallback) that has a recent suspicious base finding, emit a
// single escalated Critical correlated finding naming the base reason, the dst,
// and the binary, with the lineage in Related. ok is false when there is no
// recent suspicious process for this connect (→ no correlated finding).
func (c *Correlator) correlateEgress(ev tetragon.Event) (report.Finding, bool) {
	st := c.resolve(ev)
	if st == nil || len(st.suspicious) == 0 {
		return report.Finding{}, false
	}
	// TTL guard: a connect from a process idle past the TTL does not correlate.
	// Aged off lastSeen (refreshed on every event) so an actively-emitting
	// suspicious process stays armed for a late beacon.
	if st.lastSeen.Before(c.now().Add(-c.ttl)) {
		return report.Finding{}, false
	}

	// Pick the strongest/first suspicion as the primary reason; T1041 if any
	// armed suspicion looked exfil-oriented, else T1071 (C2 channel).
	primary := st.suspicious[0]
	technique := "T1071"
	for _, s := range st.suspicious {
		if s.exfilish {
			technique = "T1041"
			primary = s
			break
		}
	}

	dst := ev.Dst
	if ev.DstPort != 0 {
		if dst != "" {
			dst = fmt.Sprintf("%s:%d", ev.Dst, ev.DstPort)
		} else {
			dst = fmt.Sprintf(":%d", ev.DstPort)
		}
	}
	if dst == "" {
		dst = "an external endpoint"
	}

	// Latch per (exec_id, dst): a beaconing implant reconnects to the same dst
	// repeatedly; emit the correlated finding once per distinct dst and suppress
	// identical re-emits so the collector isn't flooded with duplicates. A NEW
	// dst still correlates. The set is bounded by maxCorrelatedDsts.
	if st.correlatedDsts[dst] {
		return report.Finding{}, false
	}
	if st.correlatedDsts == nil {
		st.correlatedDsts = make(map[string]bool)
	}
	if len(st.correlatedDsts) < maxCorrelatedDsts {
		st.correlatedDsts[dst] = true
	}

	binary := st.binary
	if binary == "" {
		binary = ev.Binary
	}

	f := report.Finding{
		Check:      "realtime.correlated",
		Severity:   report.SeverityCritical, // escalated from the base
		Title:      "suspicious process then connected out",
		Detail:     fmt.Sprintf("%s (%s) connected to %s", binary, primary.reason, dst),
		Path:       binary,
		Technique:  technique,
		Confidence: "high",
	}
	f.Related = append(f.Related, "base: "+primary.reason)
	if primary.technique != "" {
		f.Related = append(f.Related, "base technique="+primary.technique)
	}
	f.Related = append(f.Related, "dst="+dst)
	if lineage, ancestorFlagged := c.lineage(st); len(lineage) > 1 {
		f.Related = append(f.Related, "lineage: "+strings.Join(lineage, " ← "))
		if ancestorFlagged {
			f.Related = append(f.Related, "ancestor previously flagged suspicious")
		}
	}
	return f, true
}

// resolve finds the process state a connect event belongs to: by exec_id first,
// then by the pid→exec_id index (handles export shapes where a connect carries a
// pid but no exec_id).
func (c *Correlator) resolve(ev tetragon.Event) *procState {
	if ev.ExecID != "" {
		if st := c.byExec[ev.ExecID]; st != nil {
			return st
		}
	}
	if ev.Pid != 0 {
		if ex, ok := c.pidIndex[ev.Pid]; ok {
			return c.byExec[ex]
		}
	}
	return nil
}

// lineage walks the parent-exec_id chain from st up to the root (bounded depth),
// returning the binaries (with exec_ids) youngest-first and whether ANY ancestor
// (excluding st itself) was flagged suspicious.
func (c *Correlator) lineage(st *procState) (chain []string, ancestorFlagged bool) {
	seen := map[string]bool{}
	cur := st
	for depth := 0; cur != nil && depth < maxLineageDepth; depth++ {
		if seen[cur.execID] {
			break // cycle guard
		}
		seen[cur.execID] = true
		chain = append(chain, label(cur))
		if depth > 0 && len(cur.suspicious) > 0 {
			ancestorFlagged = true
		}
		if cur.parentExecID == "" {
			break
		}
		cur = c.byExec[cur.parentExecID]
	}
	return chain, ancestorFlagged
}

// label renders one process for a lineage line: "binary[execid-tail]".
func label(st *procState) string {
	b := st.binary
	if b == "" {
		b = "?"
	}
	if st.execID == "" {
		return b
	}
	return b + "[" + execTail(st.execID) + "]"
}

// execTail shortens an exec_id (which can be long, base64-ish) to its last
// colon-separated component for readable lineage lines.
func execTail(execID string) string {
	if i := strings.LastIndexByte(execID, ':'); i >= 0 && i < len(execID)-1 {
		return execID[i+1:]
	}
	return execID
}

// suspicionFor reports whether a base finding arms an egress correlation, and
// the suspicion it records. The armed signals are the high-fidelity
// process-origin ones: staging-dir / fileless exec and an unrecognized bpf load.
func suspicionFor(f report.Finding) (suspicion, bool) {
	switch f.Check {
	case "realtime.exec":
		return suspicion{reason: f.Title, technique: f.Technique, exfilish: false}, true
	case "realtime.bpf":
		// Only the real (non-allowlisted) load arms it; an allowlisted load is Info.
		if f.Severity >= report.SeverityHigh {
			return suspicion{reason: f.Title, technique: f.Technique, exfilish: false}, true
		}
	}
	return suspicion{}, false
}

// baseConfidence assigns a default confidence to a base finding by severity, so
// even un-correlated findings carry the contract's low/medium signal. A single
// stateless rule never claims "high" on its own — that tier is reserved for the
// correlator (a corroborated / lineage-escalated finding). High/Critical base
// findings are "medium"; Medium and below are "low".
func baseConfidence(f report.Finding) string {
	if f.Severity >= report.SeverityHigh {
		return "medium"
	}
	return "low"
}

// bumpConfidence raises a confidence one tier (low→medium→high).
func bumpConfidence(c string) string {
	switch c {
	case "low", "":
		return "medium"
	default:
		return "high"
	}
}
