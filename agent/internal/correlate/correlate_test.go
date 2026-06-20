package correlate

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
	"github.com/mtclinton/defensive-suite/agent/internal/rules"
	"github.com/mtclinton/defensive-suite/agent/internal/tetragon"
)

func testCfg() rules.Config {
	return rules.Config{
		StagingDirs:  []string{"/tmp/", "/dev/shm/", "/var/tmp/"},
		BPFLoadFuncs: []string{"security_bpf_prog_load"},
		BPFAllowlist: []string{"/usr/bin/cilium-agent"},
		WriteFuncs:   []string{"security_file_permission"},
		SensitivePaths: []string{
			"/etc/ld.so.preload",
		},
	}
}

// a clock we can advance deterministically.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock {
	return &clock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
}

// findCorrelated returns the single realtime.correlated finding, failing if the
// count is not exactly one.
func correlated(t *testing.T, fs []report.Finding) report.Finding {
	t.Helper()
	var out []report.Finding
	for _, f := range fs {
		if f.Check == "realtime.correlated" {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("want exactly 1 correlated finding, got %d in %+v", len(out), fs)
	}
	return out[0]
}

// confOf returns the confidence of the first finding, for error messages.
func confOf(fs []report.Finding) string {
	if len(fs) == 0 {
		return "<none>"
	}
	return fs[0].Confidence
}

func hasCorrelated(fs []report.Finding) bool {
	for _, f := range fs {
		if f.Check == "realtime.correlated" {
			return true
		}
	}
	return false
}

// Correlation A: a suspicious exec (staging dir, exec_id X) followed by a
// connect for exec_id X yields one Critical correlated finding naming the dst,
// at high confidence.
func TestExecThenConnectCorrelates(t *testing.T) {
	cl := newClock()
	c := New(0, 0, cl.now)

	exec := tetragon.Event{Kind: "exec", Binary: "/tmp/.x/payload", ExecID: "X", Pid: 1337}
	base := c.Process(exec, testCfg())
	if hasCorrelated(base) {
		t.Fatal("an exec alone must not produce a correlated finding")
	}
	// The base staging-dir finding must still emit, unchanged in essence.
	if len(base) != 1 || base[0].Check != "realtime.exec" || base[0].Severity != report.SeverityMedium {
		t.Fatalf("base finding changed: %+v", base)
	}

	conn := tetragon.Event{Kind: "connect", Binary: "/tmp/.x/payload", ExecID: "X", Pid: 1337, Dst: "1.2.3.4", DstPort: 443}
	got := c.Process(conn, testCfg())
	f := correlated(t, got)
	if f.Severity != report.SeverityCritical {
		t.Errorf("correlated finding must be Critical: %+v", f)
	}
	if f.Confidence != "high" {
		t.Errorf("correlated confidence=%q (want high)", f.Confidence)
	}
	if f.Technique != "T1071" {
		t.Errorf("technique=%q (want T1071 C2)", f.Technique)
	}
	if !strings.Contains(f.Detail, "1.2.3.4:443") {
		t.Errorf("detail must name the dst: %q", f.Detail)
	}
	if !strings.Contains(f.Detail, "/tmp/.x/payload") {
		t.Errorf("detail must name the binary: %q", f.Detail)
	}
	var relatedDst bool
	for _, r := range f.Related {
		if strings.Contains(r, "1.2.3.4:443") {
			relatedDst = true
		}
	}
	if !relatedDst {
		t.Errorf("Related must carry the dst evidence: %v", f.Related)
	}
}

// Fileless exec arms the correlation too.
func TestFilelessExecThenConnectCorrelates(t *testing.T) {
	cl := newClock()
	c := New(0, 0, cl.now)
	c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/x (deleted)", ExecID: "F", Pid: 50}, testCfg())
	got := c.Process(tetragon.Event{Kind: "connect", ExecID: "F", Pid: 50, Dst: "9.9.9.9", DstPort: 8080}, testCfg())
	f := correlated(t, got)
	if f.Severity != report.SeverityCritical || f.Confidence != "high" {
		t.Errorf("fileless→connect should be Critical/high: %+v", f)
	}
}

// A bpf load (unrecognized loader) arms the correlation.
func TestBPFLoadThenConnectCorrelates(t *testing.T) {
	cl := newClock()
	c := New(0, 0, cl.now)
	c.Process(tetragon.Event{Kind: "kprobe", Function: "security_bpf_prog_load", Binary: "/usr/bin/evil", ExecID: "B", Pid: 70}, testCfg())
	got := c.Process(tetragon.Event{Kind: "connect", ExecID: "B", Pid: 70, Dst: "5.5.5.5", DstPort: 4444}, testCfg())
	f := correlated(t, got)
	if f.Severity != report.SeverityCritical || f.Confidence != "high" {
		t.Errorf("bpf-load→connect should be Critical/high: %+v", f)
	}
}

// An allowlisted bpf load is Info and must NOT arm the correlation.
func TestAllowlistedBPFLoadDoesNotArm(t *testing.T) {
	cl := newClock()
	c := New(0, 0, cl.now)
	c.Process(tetragon.Event{Kind: "kprobe", Function: "security_bpf_prog_load", Binary: "/usr/bin/cilium-agent", ExecID: "A", Pid: 80}, testCfg())
	got := c.Process(tetragon.Event{Kind: "connect", ExecID: "A", Pid: 80, Dst: "5.5.5.5", DstPort: 80}, testCfg())
	if hasCorrelated(got) {
		t.Errorf("an allowlisted (Info) bpf load must not arm correlation: %+v", got)
	}
}

// A connect for a process with no prior suspicious exec yields NO correlated
// finding (only/at-most a base finding — here none).
func TestConnectWithoutPriorSuspiciousExec(t *testing.T) {
	cl := newClock()
	c := New(0, 0, cl.now)
	// A benign exec first (not under a staging dir).
	c.Process(tetragon.Event{Kind: "exec", Binary: "/usr/bin/curl", ExecID: "Y", Pid: 200}, testCfg())
	got := c.Process(tetragon.Event{Kind: "connect", ExecID: "Y", Pid: 200, Dst: "1.1.1.1", DstPort: 443}, testCfg())
	if hasCorrelated(got) {
		t.Errorf("connect from a benign process must not correlate: %+v", got)
	}
	// A connect for a totally unknown exec_id likewise must not correlate.
	if got := c.Process(tetragon.Event{Kind: "connect", ExecID: "ZZZ", Pid: 999, Dst: "2.2.2.2", DstPort: 53}, testCfg()); hasCorrelated(got) {
		t.Errorf("connect from an unknown process must not correlate: %+v", got)
	}
}

// TTL eviction: a connect long after the suspicious exec (clock advanced past
// TTL) does NOT correlate, and the stale state is evicted (memory bounded).
func TestTTLEvictionStopsCorrelation(t *testing.T) {
	cl := newClock()
	c := New(0, 100*time.Millisecond, cl.now)
	c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/.x/payload", ExecID: "X", Pid: 1337}, testCfg())
	if c.Tracked() != 1 {
		t.Fatalf("exec should be tracked: %d", c.Tracked())
	}
	cl.add(200 * time.Millisecond) // advance past TTL
	got := c.Process(tetragon.Event{Kind: "connect", ExecID: "X", Pid: 1337, Dst: "1.2.3.4", DstPort: 443}, testCfg())
	if hasCorrelated(got) {
		t.Errorf("a connect past the TTL must not correlate: %+v", got)
	}
	// The expired exec state must have been evicted before the connect ran. (Only
	// the connect's own freshly-tracked state remains.)
	if _, stillThere := c.byExec["X"]; stillThere {
		// X may be re-tracked by the connect itself, but with a fresh first-seen and
		// NO suspicious findings — so it still must not correlate. Assert that.
		if len(c.byExec["X"].suspicious) != 0 {
			t.Errorf("expired suspicious state should not survive: %+v", c.byExec["X"])
		}
	}
}

// Bounded/cap: feeding far more exec_ids than the cap keeps memory bounded —
// Tracked never exceeds the cap.
func TestBoundedByCap(t *testing.T) {
	cl := newClock()
	const cap = 64
	c := New(cap, time.Hour, cl.now)
	for i := 0; i < cap*10; i++ {
		ev := tetragon.Event{Kind: "exec", Binary: "/tmp/p", ExecID: fmt.Sprintf("E%d", i), Pid: uint32(i + 1)}
		c.Process(ev, testCfg())
		if c.Tracked() > cap {
			t.Fatalf("tracked %d exceeds cap %d at i=%d", c.Tracked(), cap, i)
		}
	}
	if c.Tracked() != cap {
		t.Errorf("after overflow, tracked=%d (want exactly cap %d)", c.Tracked(), cap)
	}
	// The pid index must not grow unbounded either: evicted processes' pids are
	// pruned, so it stays at most the cap.
	if len(c.pidIndex) > cap {
		t.Errorf("pid index grew unbounded: %d > cap %d", len(c.pidIndex), cap)
	}
}

// Lineage chain is assembled across the parent-exec_id chain, and an
// ancestor that was itself flagged suspicious escalates confidence.
func TestLineageChainAndAncestorEscalation(t *testing.T) {
	cl := newClock()
	c := New(0, 0, cl.now)
	cfg := testCfg()

	// sshd (S) → bash (Bsh) → suspicious staging exec curl (C). sshd is benign,
	// bash is benign, curl is the suspicious leaf.
	c.Process(tetragon.Event{Kind: "exec", Binary: "/usr/sbin/sshd", ExecID: "S", Pid: 1}, cfg)
	c.Process(tetragon.Event{Kind: "exec", Binary: "/bin/bash", ExecID: "Bsh", ParentExecID: "S", Pid: 2}, cfg)
	leaf := c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/curl", ExecID: "C", ParentExecID: "Bsh", Pid: 3}, cfg)

	// The base staging-dir finding on curl must carry the lineage in Related.
	if len(leaf) != 1 {
		t.Fatalf("want 1 base finding on the suspicious leaf, got %d: %+v", len(leaf), leaf)
	}
	var lineageLine string
	for _, r := range leaf[0].Related {
		if strings.HasPrefix(r, "lineage:") {
			lineageLine = r
		}
	}
	if lineageLine == "" {
		t.Fatalf("base finding missing lineage Related line: %+v", leaf[0].Related)
	}
	for _, want := range []string{"curl", "bash", "sshd"} {
		if !strings.Contains(lineageLine, want) {
			t.Errorf("lineage %q missing %q", lineageLine, want)
		}
	}

	// Now an ancestor itself flagged suspicious: spawn a child of the suspicious
	// curl. Its base finding must escalate confidence one tier because an ancestor
	// (curl) was flagged. A Medium staging child ("low" base) → "medium".
	child := c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/child", ExecID: "Ch", ParentExecID: "C", Pid: 4}, cfg)
	if len(child) != 1 {
		t.Fatalf("want 1 base finding on child, got %+v", child)
	}
	if child[0].Confidence != "medium" {
		t.Errorf("ancestor-flagged Medium child confidence=%q (want bumped low→medium)", child[0].Confidence)
	}
	var ancestorNote bool
	for _, r := range child[0].Related {
		if strings.Contains(r, "ancestor") {
			ancestorNote = true
		}
	}
	if !ancestorNote {
		t.Errorf("child finding should note the flagged ancestor: %+v", child[0].Related)
	}

	// A High-severity child (fileless, "medium" base) under the same flagged
	// ancestor escalates all the way to "high".
	hi := c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/x (deleted)", ExecID: "Hi", ParentExecID: "C", Pid: 5}, cfg)
	if len(hi) != 1 || hi[0].Confidence != "high" {
		t.Errorf("ancestor-flagged High child confidence=%q (want bumped medium→high): %+v", confOf(hi), hi)
	}
}

// Base findings still emit unchanged (check/severity/technique) through the
// correlator — correlation ADDS, it does not replace.
func TestBaseFindingsUnchanged(t *testing.T) {
	cl := newClock()
	c := New(0, 0, cl.now)
	cfg := testCfg()

	cases := []struct {
		ev   tetragon.Event
		chk  string
		sev  report.Severity
		tech string
	}{
		{tetragon.Event{Kind: "exec", Binary: "/tmp/.x/p", ExecID: "1"}, "realtime.exec", report.SeverityMedium, "T1059"},
		{tetragon.Event{Kind: "exec", Binary: "/dev/shm/x (deleted)", ExecID: "2"}, "realtime.exec", report.SeverityHigh, "T1620"},
		{tetragon.Event{Kind: "kprobe", Function: "security_bpf_prog_load", Binary: "/usr/bin/evil", ExecID: "3"}, "realtime.bpf", report.SeverityHigh, "T1014"},
		{tetragon.Event{Kind: "kprobe", Function: "security_file_permission", Binary: "/usr/bin/tee", Paths: []string{"/etc/ld.so.preload"}, ExecID: "4"}, "realtime.write", report.SeverityCritical, "T1574.006"},
	}
	for _, tc := range cases {
		got := c.Process(tc.ev, cfg)
		// Exactly one base finding, no spurious correlated finding.
		if hasCorrelated(got) {
			t.Errorf("%s: unexpected correlated finding: %+v", tc.chk, got)
		}
		if len(got) != 1 {
			t.Fatalf("%s: want 1 base finding, got %d: %+v", tc.chk, len(got), got)
		}
		f := got[0]
		if f.Check != tc.chk || f.Severity != tc.sev || f.Technique != tc.tech {
			t.Errorf("base finding changed: got %+v want check=%s sev=%v tech=%s", f, tc.chk, tc.sev, tc.tech)
		}
	}

	// A clean exec and an exit still yield nothing.
	if got := c.Process(tetragon.Event{Kind: "exec", Binary: "/usr/bin/ls", ExecID: "9"}, cfg); len(got) != 0 {
		t.Errorf("clean exec should yield nothing: %+v", got)
	}
	if got := c.Process(tetragon.Event{Kind: "exit", Binary: "/usr/bin/ls", ExecID: "9"}, cfg); len(got) != 0 {
		t.Errorf("exit should yield nothing: %+v", got)
	}
}

// The pid fallback: a connect that carries a pid but no exec_id is still
// attributed to the process that most recently exec'd under that pid.
func TestConnectPidFallback(t *testing.T) {
	cl := newClock()
	c := New(0, 0, cl.now)
	c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/.x/payload", ExecID: "X", Pid: 4242}, testCfg())
	// connect with the pid only.
	got := c.Process(tetragon.Event{Kind: "connect", Pid: 4242, Dst: "3.3.3.3", DstPort: 1337}, testCfg())
	f := correlated(t, got)
	if f.Severity != report.SeverityCritical || !strings.Contains(f.Detail, "3.3.3.3:1337") {
		t.Errorf("pid-fallback correlation failed: %+v", f)
	}
}

// A connect with no destination at all still correlates (the suspicious exec is
// the signal); the detail degrades gracefully to a generic endpoint phrase.
func TestConnectNoDestinationStillCorrelates(t *testing.T) {
	cl := newClock()
	c := New(0, 0, cl.now)
	c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/.x/payload", ExecID: "X", Pid: 1}, testCfg())
	got := c.Process(tetragon.Event{Kind: "connect", ExecID: "X", Pid: 1}, testCfg())
	f := correlated(t, got)
	if f.Severity != report.SeverityCritical {
		t.Errorf("connect with no dst should still correlate: %+v", f)
	}
	if !strings.Contains(f.Detail, "external endpoint") {
		t.Errorf("missing-dst detail should degrade gracefully: %q", f.Detail)
	}
}

// Fix 1+2: a loader looping security_bpf_prog_load under ONE exec_id must not
// grow procState.suspicious without bound (dedup + cap), and correlation still
// fires. Without the fix this slice grows one entry per load → OOM.
func TestBPFLoadSuspicionBoundedAndStillCorrelates(t *testing.T) {
	cl := newClock()
	c := New(0, time.Hour, cl.now)
	cfg := testCfg()

	// Many identical realtime.bpf arming findings under one exec_id.
	for i := 0; i < 10000; i++ {
		c.Process(tetragon.Event{Kind: "kprobe", Function: "security_bpf_prog_load", Binary: "/usr/bin/evil", ExecID: "B", Pid: 70}, cfg)
	}
	st := c.byExec["B"]
	if st == nil {
		t.Fatal("process B should be tracked")
	}
	if len(st.suspicious) > maxSuspicionsPerProc {
		t.Errorf("suspicious grew unbounded: len=%d > cap %d", len(st.suspicious), maxSuspicionsPerProc)
	}
	// Identical suspicions dedup to a single entry.
	if len(st.suspicious) != 1 {
		t.Errorf("identical suspicions should dedup to 1, got %d", len(st.suspicious))
	}
	// Correlation still fires on the subsequent connect.
	got := c.Process(tetragon.Event{Kind: "connect", ExecID: "B", Pid: 70, Dst: "5.5.5.5", DstPort: 4444}, cfg)
	f := correlated(t, got)
	if f.Severity != report.SeverityCritical {
		t.Errorf("looped bpf load → connect should still correlate Critical: %+v", f)
	}
}

// Fix 3: a process that stays ACTIVE past firstSeen+TTL (lastSeen refreshed)
// still correlates a later connect; a truly idle one is evicted.
func TestActiveProcessStaysArmedPastFirstSeenTTL(t *testing.T) {
	cl := newClock()
	c := New(0, 100*time.Millisecond, cl.now)
	cfg := testCfg()

	c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/.x/payload", ExecID: "X", Pid: 1337}, cfg)
	// Keep the process active, advancing the clock past the original firstSeen+TTL
	// window each step. lastSeen keeps refreshing, so it must stay armed.
	for i := 0; i < 5; i++ {
		cl.add(80 * time.Millisecond) // < TTL since last activity
		c.Process(tetragon.Event{Kind: "kprobe", Function: "security_bpf_prog_load", Binary: "/usr/bin/x", ExecID: "X", Pid: 1337}, cfg)
	}
	// Total elapsed (400ms) is well past firstSeen+TTL (100ms) but the process
	// never went idle longer than TTL, so a connect now must still correlate.
	cl.add(80 * time.Millisecond)
	got := c.Process(tetragon.Event{Kind: "connect", ExecID: "X", Pid: 1337, Dst: "1.2.3.4", DstPort: 443}, cfg)
	if !hasCorrelated(got) {
		t.Errorf("an active-then-beacon process should still correlate: %+v", got)
	}

	// A second process that goes idle > TTL is evicted and does not correlate.
	c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/.y/idle", ExecID: "Y", Pid: 2000}, cfg)
	cl.add(200 * time.Millisecond) // idle past TTL
	got = c.Process(tetragon.Event{Kind: "connect", ExecID: "Y", Pid: 2000, Dst: "9.9.9.9", DstPort: 80}, cfg)
	if hasCorrelated(got) {
		t.Errorf("an idle-past-TTL process must be evicted, not correlate: %+v", got)
	}
}

// Fix 4: at the cap, eviction on a lastSeen tie is deterministic (by execID),
// not dependent on Go map iteration order. Repeated runs must evict the same key.
func TestCapEvictionDeterministicOnTie(t *testing.T) {
	cl := newClock()
	// Two procs admitted at the SAME lastSeen, then a third forces eviction.
	run := func() string {
		c := New(2, time.Hour, cl.now)
		cfg := testCfg()
		// A and B at identical now().
		c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/a", ExecID: "A", Pid: 1}, cfg)
		c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/b", ExecID: "B", Pid: 2}, cfg)
		// Admitting C evicts the deterministic-oldest tie (A < B → evict A).
		c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/c", ExecID: "C", Pid: 3}, cfg)
		if _, ok := c.byExec["A"]; ok {
			return "A"
		}
		if _, ok := c.byExec["B"]; ok {
			return "B"
		}
		return "?"
	}
	first := run()
	if first != "B" {
		t.Errorf("tie-break should evict A (smallest execID), leaving B; got survivor %q", first)
	}
	for i := 0; i < 20; i++ {
		if got := run(); got != first {
			t.Fatalf("non-deterministic eviction: run %d survivor %q != %q", i, got, first)
		}
	}
}

// Fix 6: a beaconing implant connecting repeatedly to the SAME dst yields ONE
// correlated finding; a connect to a NEW dst yields a second.
func TestDuplicateBeaconSuppressedPerDst(t *testing.T) {
	cl := newClock()
	c := New(0, time.Hour, cl.now)
	cfg := testCfg()

	c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/.x/payload", ExecID: "X", Pid: 1}, cfg)

	beacon := tetragon.Event{Kind: "connect", ExecID: "X", Pid: 1, Dst: "1.2.3.4", DstPort: 443}
	first := c.Process(beacon, cfg)
	if !hasCorrelated(first) {
		t.Fatalf("first beacon should correlate: %+v", first)
	}
	second := c.Process(beacon, cfg)
	if hasCorrelated(second) {
		t.Errorf("repeat beacon to the SAME dst must be suppressed: %+v", second)
	}
	// A connect to a NEW dst correlates again.
	third := c.Process(tetragon.Event{Kind: "connect", ExecID: "X", Pid: 1, Dst: "5.6.7.8", DstPort: 8080}, cfg)
	if !hasCorrelated(third) {
		t.Errorf("a connect to a NEW dst should correlate: %+v", third)
	}
	// And that new dst is itself latched.
	fourth := c.Process(tetragon.Event{Kind: "connect", ExecID: "X", Pid: 1, Dst: "5.6.7.8", DstPort: 8080}, cfg)
	if hasCorrelated(fourth) {
		t.Errorf("repeat to the new dst must also be suppressed: %+v", fourth)
	}
}

// Fix 7: after a process exits, a later no-exec_id connect on that (not-yet-
// reused) pid must NOT resolve to the dead suspicious process.
func TestExitClearsPidIndexNoMisattribution(t *testing.T) {
	cl := newClock()
	c := New(0, time.Hour, cl.now)
	cfg := testCfg()

	const pid = 4242
	c.Process(tetragon.Event{Kind: "exec", Binary: "/tmp/.x/payload", ExecID: "X", Pid: pid}, cfg)
	// Sanity: while alive, a pid-only connect WOULD correlate.
	if _, ok := c.pidIndex[pid]; !ok {
		t.Fatalf("pid %d should be indexed while alive", pid)
	}
	// The process exits.
	c.Process(tetragon.Event{Kind: "exit", Binary: "/tmp/.x/payload", ExecID: "X", Pid: pid}, cfg)
	if ex, ok := c.pidIndex[pid]; ok {
		t.Errorf("exit must drop the pid-index entry, still maps to %q", ex)
	}
	// A later no-exec_id connect on that pid (before reuse) must NOT correlate.
	got := c.Process(tetragon.Event{Kind: "connect", Pid: pid, Dst: "6.6.6.6", DstPort: 1337}, cfg)
	if hasCorrelated(got) {
		t.Errorf("no-exec_id connect after exit must not misattribute: %+v", got)
	}
}

// Defaults are applied when zero values are passed to New.
func TestNewDefaults(t *testing.T) {
	c := New(0, 0, nil)
	if c.maxProcs != DefaultMaxProcs || c.ttl != DefaultTTL || c.now == nil {
		t.Errorf("defaults not applied: maxProcs=%d ttl=%v nowNil=%v", c.maxProcs, c.ttl, c.now == nil)
	}
}
