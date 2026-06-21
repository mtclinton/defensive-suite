package respond

import (
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// --- test fixtures ---

var testNow = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// baseAutoConfig is a shadow-mode config with the standard staging dirs and a
// generous rate budget, suitable for the gate tests.
func baseAutoConfig() AutoConfig {
	return AutoConfig{
		Mode:        ModeShadow,
		StagingDirs: []string{"/tmp/", "/dev/shm/", "/var/tmp/"},
		MgmtSubnets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		StaleTTL:    5 * time.Second,
		RateMax:     3,
		RateWindow:  300 * time.Second,
		DisablePath: "/run/agentd/autoresponse.disabled",
	}
}

// eligibleFinding builds a realtime.correlated finding that passes EVERY gate
// (fileless base, external dst, fresh event time, exec_id-resolved, live staging
// process owned by the same UID). Individual tests mutate one dimension to
// exercise a single gate.
func eligibleFinding() report.Finding {
	return report.Finding{
		Check:      "realtime.correlated",
		Severity:   report.SeverityCritical,
		Confidence: "high",
		Title:      "suspicious process then connected out",
		Path:       "/tmp/.x/payload", // attacker-influenced — NEVER used as target
		Technique:  "T1041",
		Related: []string{
			"base: fileless execution (deleted or memfd binary)",
			"base technique=T1620",
			"dst=8.8.8.8:443",
			"resolved=exec_id",
			"lineage: payload[c] ← bash[b] ← sshd[a]",
		},
		AutoMeta: &report.AutoMeta{
			ExecID:     "c",
			Pid:        1337,
			StartTime:  5000, // matches liveStagingProc's pid 1337 (G5 identity bind)
			DetectedAt: testNow,
			Dst:        "8.8.8.8", // bare IP; port carried in DstPort + the dst= Related
			DstPort:    443,
		},
	}
}

// liveStagingProc is a fakeProc where pid 1337 is a live, staging-resident, uid-
// 1000 process (the connecting process and its candidate target are the same in
// Increment 1, so a single entry passes the same-UID check).
func liveStagingProc() fakeProc {
	return fakeProc{1337: {Exe: "/tmp/.x/payload", UID: 1000, StartTime: 5000, Live: true}}
}

// newTestBridge builds a shadow Bridge with a fixed clock, an injected
// always-absent disarm latch, and the given /proc fake.
func newTestBridge(cfg AutoConfig, proc procResolver) *Bridge {
	return NewBridge(cfg, func() time.Time { return testNow }, func(string) bool { return false }, proc)
}

// shadowFindings filters out only the would-act shadow findings.
func shadowFindings(out []report.Finding) []report.Finding {
	var s []report.Finding
	for _, f := range out {
		if f.Check == checkShadow {
			s = append(s, f)
		}
	}
	return s
}

// --- the all-gates-pass happy path ---

func TestConsiderEligibleEmitsShadowWouldQuarantine(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	out := b.Consider([]report.Finding{eligibleFinding()})
	sf := shadowFindings(out)
	if len(sf) != 1 {
		t.Fatalf("want 1 shadow would-finding, got %d: %+v", len(sf), out)
	}
	f := sf[0]
	if f.Severity != report.SeverityHigh || f.Confidence != "high" {
		t.Errorf("shadow finding should be High/high: %+v", f)
	}
	// Title names the WOULD action + the RESOLVED /proc target, not Finding.Path.
	if want := "WOULD quarantine /tmp/.x/payload"; f.Title != want {
		t.Errorf("title=%q want %q", f.Title, want)
	}
	if !relatedHas(f.Related, "mode=shadow") || !relatedHas(f.Related, "would_action=quarantine") {
		t.Errorf("related missing mode/would_action: %v", f.Related)
	}
	if relatedValue(f.Related, "resolved_target=") != "/tmp/.x/payload" {
		t.Errorf("resolved_target not the /proc exe: %v", f.Related)
	}
}

// --- mode behavior ---

func TestModeOffEmitsNothing(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.Mode = ModeOff
	b := newTestBridge(cfg, liveStagingProc())
	if out := b.Consider([]report.Finding{eligibleFinding()}); len(out) != 0 {
		t.Errorf("ModeOff must emit nothing, got %+v", out)
	}
}

func TestModeDryRunEmitsShadow(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.Mode = ModeDryRun
	b := newTestBridge(cfg, liveStagingProc())
	out := shadowFindings(b.Consider([]report.Finding{eligibleFinding()}))
	if len(out) != 1 {
		t.Fatalf("dry-run should emit a would-finding, got %+v", out)
	}
	if !relatedHas(out[0].Related, "mode=dry-run") {
		t.Errorf("dry-run finding should carry mode=dry-run: %v", out[0].Related)
	}
}

// --- STRUCTURAL no-executor invariant: the Bridge type has NO executor/
// responder field, and even a forced "armed" mode only emits findings. ---

func TestBridgeHasNoExecutorField(t *testing.T) {
	bt := reflect.TypeOf(Bridge{})
	for i := 0; i < bt.NumField(); i++ {
		f := bt.Field(i)
		switch f.Type.String() {
		case "respond.Executor", "*respond.Responder", "respond.Responder", "*respond.RealExecutor", "*respond.FakeExecutor":
			t.Fatalf("Bridge MUST NOT hold an actuator reference; found field %q of type %s", f.Name, f.Type)
		}
		// Defensive: also reject any field whose type name hints at execution.
		name := f.Type.String()
		if name == "respond.Executor" {
			t.Fatalf("Bridge holds an Executor via field %q", f.Name)
		}
	}
}

// Even if an operator somehow forced an armed mode into the Bridge (which the
// run/preflight paths refuse), the Bridge can ONLY emit findings — there is no
// actuator to reach. We assert: a Bridge constructed with ModeArmed still just
// produces report.Findings and never panics / never has an exec path.
func TestForcedArmedModeOnlyEmitsFindings(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.Mode = ModeArmed // not reachable via ParseMode; force it directly
	b := newTestBridge(cfg, liveStagingProc())
	out := b.Consider([]report.Finding{eligibleFinding()})
	// Whatever it emits, it is ONLY report.Findings (the return type), and the
	// fake /proc was never asked to do anything but resolve (it has no act method).
	for _, f := range out {
		if f.Check != checkShadow && f.Check != checkThrottled {
			t.Errorf("forced-armed bridge emitted an unexpected check %q (still only a finding, but unexpected)", f.Check)
		}
	}
}

// --- G1: only realtime.correlated is auto-eligible (never a confidence check) ---

func TestG1OnlyCorrelated(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	for _, chk := range []string{"realtime.exec", "realtime.bpf", "realtime.write", ""} {
		f := eligibleFinding()
		f.Check = chk
		if out := b.Consider([]report.Finding{f}); len(out) != 0 {
			t.Errorf("check %q must not be auto-eligible: %+v", chk, out)
		}
	}
}

// A high-confidence base finding (NOT correlated) must never reach the auto path
// — G1 is load-bearing, not reducible to confidence==high.
func TestG1HighConfidenceBaseFindingIneligible(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	f := eligibleFinding()
	f.Check = "realtime.exec" // a base finding bumped to high via lineage
	if out := b.Consider([]report.Finding{f}); len(out) != 0 {
		t.Errorf("a high-confidence BASE finding must not auto-act: %+v", out)
	}
}

// --- G2/G3 (the same enforced bit, asserted defensively) ---

func TestG2G3RequireHighCritical(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	lowConf := eligibleFinding()
	lowConf.Confidence = "medium"
	if out := shadowFindings(b.Consider([]report.Finding{lowConf})); len(out) != 0 {
		t.Errorf("non-high confidence must not auto-act: %+v", out)
	}
	notCrit := eligibleFinding()
	notCrit.Severity = report.SeverityHigh
	if out := shadowFindings(b.Consider([]report.Finding{notCrit})); len(out) != 0 {
		t.Errorf("non-critical severity must not auto-act: %+v", out)
	}
}

// --- G4: resolved=pid or absent → alert-only ---

func TestG4RequiresExecIDResolution(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	// resolved=pid
	pidOnly := eligibleFinding()
	pidOnly.Related = replaceRelated(pidOnly.Related, "resolved=exec_id", "resolved=pid")
	if out := shadowFindings(b.Consider([]report.Finding{pidOnly})); len(out) != 0 {
		t.Errorf("resolved=pid must be alert-only (no would-act): %+v", out)
	}
	// resolved absent
	noRes := eligibleFinding()
	noRes.Related = dropRelated(noRes.Related, "resolved=exec_id")
	if out := shadowFindings(b.Consider([]report.Finding{noRes})); len(out) != 0 {
		t.Errorf("absent resolved marker must be alert-only: %+v", out)
	}
}

// --- G5: live, staging-resident, same-UID, non-protected target ---

func TestG5DeadProcessAlertOnly(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), fakeProc{}) // pid 1337 not present → not live
	if out := shadowFindings(b.Consider([]report.Finding{eligibleFinding()})); len(out) != 0 {
		t.Errorf("a dead process must be alert-only: %+v", out)
	}
}

func TestG5NonStagingResidentAlertOnly(t *testing.T) {
	// StartTime matches AutoMeta so the identity bind passes and the STAGING gate
	// is the one that fires (forged /opt finding).
	proc := fakeProc{1337: {Exe: "/opt/app/server", UID: 1000, StartTime: 5000, Live: true}}
	b := newTestBridge(baseAutoConfig(), proc)
	if out := shadowFindings(b.Consider([]report.Finding{eligibleFinding()})); len(out) != 0 {
		t.Errorf("a non-staging-resident exe must be alert-only (forged /opt finding): %+v", out)
	}
}

func TestG5ProtectedProcessAlertOnly(t *testing.T) {
	// A process whose exe is at a REAL protected system path (here, also made
	// staging-resident so the protected backstop — not the staging gate — is what
	// fires) is alert-only. Protection is anchored to the real path, NOT a basename.
	cfg := baseAutoConfig()
	cfg.StagingDirs = append(cfg.StagingDirs, "/usr/sbin/")
	proc := fakeProc{1337: {Exe: "/usr/sbin/sshd", UID: 1000, StartTime: 5000, Live: true}}
	b := newTestBridge(cfg, proc)
	if out := shadowFindings(b.Consider([]report.Finding{eligibleFinding()})); len(out) != 0 {
		t.Errorf("a protected process (real sshd path) must be alert-only: %+v", out)
	}
}

// FIX 4: the inverse — a staging-resident dropper merely NAMED a protected
// basename ("bash") must NOT be treated as protected, so it remains auto-eligible.
// (The old basename-keyed protected set let this evade auto-eligibility.)
func TestG5StagingExeNamedBashIsNotProtected(t *testing.T) {
	proc := fakeProc{1337: {Exe: "/tmp/.x/bash", UID: 1000, StartTime: 5000, Live: true}}
	b := newTestBridge(baseAutoConfig(), proc)
	out := shadowFindings(b.Consider([]report.Finding{eligibleFinding()}))
	if len(out) != 1 {
		t.Fatalf("a staging dropper NAMED bash must NOT be protected (still auto-eligible): %+v", out)
	}
	if out[0].Title != "WOULD quarantine /tmp/.x/bash" {
		t.Errorf("would-quarantine the staging /tmp bash, got title %q", out[0].Title)
	}
}

func TestG5NeverQuarantineListAlertOnly(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.NeverQuarantine = []string{"/tmp/.x"}
	proc := liveStagingProc() // /tmp/.x/payload is under the never-list prefix
	b := newTestBridge(cfg, proc)
	if out := shadowFindings(b.Consider([]report.Finding{eligibleFinding()})); len(out) != 0 {
		t.Errorf("never-quarantine list must force alert-only: %+v", out)
	}
}

// --- G6: event-time staleness (best-effort), zero time fails closed ---

func TestG6StaleEventTimeAlertOnly(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	stale := eligibleFinding()
	stale.AutoMeta.DetectedAt = testNow.Add(-10 * time.Second) // > 5s TTL
	if out := shadowFindings(b.Consider([]report.Finding{stale})); len(out) != 0 {
		t.Errorf("a stale event time must be alert-only: %+v", out)
	}
}

func TestG6ZeroEventTimeFailsClosed(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	noTime := eligibleFinding()
	noTime.AutoMeta.DetectedAt = time.Time{}
	if out := shadowFindings(b.Consider([]report.Finding{noTime})); len(out) != 0 {
		t.Errorf("a zero event time must fail closed (alert-only): %+v", out)
	}
}

// --- G7: destination class ---

func TestG7DestinationClass(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.CollectorHost = "203.0.113.9"
	cases := []struct {
		dst      string
		external bool
		desc     string
	}{
		{"8.8.8.8:443", true, "public routable"},
		{"1.1.1.1", true, "public routable no port"},
		{"127.0.0.1:443", false, "loopback"},
		{"10.1.2.3:80", false, "RFC1918 10/8"},
		{"172.16.5.5:80", false, "RFC1918 172.16/12"},
		{"192.168.1.10:80", false, "RFC1918 192.168/16"},
		{"100.100.1.1:80", false, "CGNAT 100.64/10"},
		{"169.254.1.1:80", false, "link-local"},
		{"203.0.113.9:443", false, "collector host"},
		{"", false, "empty"},
		{"an external endpoint", false, "fallback phrase"},
		{"not-an-ip:443", false, "unparseable host"},
	}
	b := newTestBridge(cfg, liveStagingProc())
	for _, tc := range cases {
		if got := b.dstIsExternal(tc.dst); got != tc.external {
			t.Errorf("dstIsExternal(%q [%s])=%v want %v", tc.dst, tc.desc, got, tc.external)
		}
	}
}

func TestG7EmptyDstAlertOnly(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	f := eligibleFinding()
	f.AutoMeta.Dst = ""
	f.Related = replaceRelated(f.Related, "dst=8.8.8.8:443", "dst=an external endpoint")
	if out := shadowFindings(b.Consider([]report.Finding{f})); len(out) != 0 {
		t.Errorf("an empty/fallback dst must be alert-only: %+v", out)
	}
}

func TestG7MgmtSubnetAlertOnly(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.MgmtSubnets = []string{"203.0.113.0/24"} // make a public-looking range mgmt
	b := NewBridge(cfg, func() time.Time { return testNow }, func(string) bool { return false }, liveStagingProc())
	f := eligibleFinding()
	f.AutoMeta.Dst = "203.0.113.50:443"
	f.Related = replaceRelated(f.Related, "dst=8.8.8.8:443", "dst=203.0.113.50:443")
	if out := shadowFindings(b.Consider([]report.Finding{f})); len(out) != 0 {
		t.Errorf("a mgmt-subnet dst must be alert-only: %+v", out)
	}
}

// --- G8 + §3.4 action selection precedence ---

func TestSelectActionPrecedence(t *testing.T) {
	cases := []struct {
		techs []string
		want  string
		desc  string
	}{
		{[]string{"T1620"}, actionWouldQuarantine, "fileless only → quarantine"},
		{[]string{"T1059"}, actionAlertOnly, "bare staging T1059 → alert-only (G8)"},
		{[]string{"T1014"}, actionAlertOnly, "bpf only → alert-only"},
		{[]string{"T1620", "T1014"}, actionAlertOnly, "bpf present → force alert-only (precedence)"},
		{[]string{"T1059", "T1620"}, actionWouldQuarantine, "staging+fileless, no bpf → quarantine"},
		{[]string{"T1059", "T1014", "T1620"}, actionAlertOnly, "any bpf → alert-only over staging+fileless"},
		{nil, actionAlertOnly, "no technique → alert-only"},
	}
	for _, tc := range cases {
		if got := selectAction(tc.techs); got != tc.want {
			t.Errorf("selectAction(%v [%s])=%q want %q", tc.techs, tc.desc, got, tc.want)
		}
	}
}

func TestG8BareStagingAlertOnly(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	f := eligibleFinding()
	f.Related = replaceRelated(f.Related, "base technique=T1620", "base technique=T1059")
	if out := shadowFindings(b.Consider([]report.Finding{f})); len(out) != 0 {
		t.Errorf("a bare staging (T1059) base must be alert-only: %+v", out)
	}
}

// §3.4: bpf-load present forces alert-only even with a co-present staging
// suspicion (quarantining the loader is theatre).
func TestBpfPresentForcesAlertOnlyDespiteStaging(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	f := eligibleFinding()
	f.Related = []string{
		"base: execution from a staging directory",
		"base technique=T1059",
		"base technique=T1014", // bpf-load present
		"dst=8.8.8.8:443",
		"resolved=exec_id",
	}
	if out := shadowFindings(b.Consider([]report.Finding{f})); len(out) != 0 {
		t.Errorf("bpf-load present must force alert-only even with staging: %+v", out)
	}
}

// --- auto-disarm latch → throttled, and it NEVER touches the shared switch ---

func TestAutoDisarmLatchThrottles(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.DisablePath = "/run/agentd/autoresponse.disabled"
	latchPresent := func(p string) bool { return p == cfg.DisablePath }
	b := NewBridge(cfg, func() time.Time { return testNow }, latchPresent, liveStagingProc())
	out := b.Consider([]report.Finding{eligibleFinding()})
	if len(shadowFindings(out)) != 0 {
		t.Errorf("with the auto-disarm latch present there must be NO would-act: %+v", out)
	}
	var throttled int
	for _, f := range out {
		if f.Check == checkThrottled {
			throttled++
		}
	}
	if throttled != 1 {
		t.Fatalf("want exactly 1 throttled finding, got %d: %+v", throttled, out)
	}
}

// A simulated auto-flood/throttle must NOT touch the shared manual kill-switch:
// a manual Responder armed with the SAME shared kill-switch path stays live and
// answers a manual request after the auto path has throttled. This is the core
// blocker #2/#4 separation.
func TestAutoFloodDoesNotDisarmManual(t *testing.T) {
	const sharedKillSwitch = "/run/agentd/response.disabled"
	const autoLatch = "/run/agentd/autoresponse.disabled"

	// Track what the auto path "touches": it must only ever read the auto latch,
	// NEVER the shared kill-switch.
	var touchedShared bool
	autoExists := func(p string) bool {
		if p == sharedKillSwitch {
			touchedShared = true
		}
		return false // neither file exists; budget is what throttles
	}

	cfg := baseAutoConfig()
	cfg.DisablePath = autoLatch
	cfg.RateMax = 1
	cfg.RateWindow = 300 * time.Second
	b := NewBridge(cfg, func() time.Time { return testNow }, autoExists, liveStagingProc())

	// Flood: many distinct eligible findings (distinct dst → distinct dedup key)
	// to exhaust the 1/300s auto budget and trip the throttle.
	for i := 0; i < 10; i++ {
		f := eligibleFinding()
		dst := "8.8.8." + string(rune('0'+i)) + ":443"
		f.AutoMeta.Dst = dst
		f.Related = replaceRelated(f.Related, "dst=8.8.8.8:443", "dst="+dst)
		// vary lineage root so dedup keys differ
		f.Related = replaceRelated(f.Related, "lineage: payload[c] ← bash[b] ← sshd[a]",
			"lineage: payload[c] ← bash[b] ← sshd["+string(rune('a'+i))+"]")
		b.Consider([]report.Finding{f})
	}

	// The auto path never read the shared kill-switch.
	if touchedShared {
		t.Error("auto path touched the SHARED manual kill-switch — it must use only the auto-only latch")
	}

	// A manual Responder sharing the SAME shared kill-switch path is still live.
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(nil), false, DefaultGuards(), func() time.Time { return testNow })
	manualSwitchExists := func(p string) bool { return false } // operator never touched it
	r.WithKillSwitch(sharedKillSwitch, manualSwitchExists)
	res := r.Respond(Request{Action: ActionQuarantine, Target: "/tmp/.x/payload"})
	if !res.OK {
		t.Errorf("manual response must stay live after an auto-flood/throttle: %+v", res)
	}
	if fake.CallCount() != 1 {
		t.Errorf("manual responder should have executed once, got %d calls", fake.CallCount())
	}
}

// --- auto-rate window: throttle emitted ONCE per window, not per attempt ---

func TestAutoRateThrottleOncePerWindow(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.RateMax = 1
	cfg.RateWindow = 300 * time.Second
	now := testNow
	clock := func() time.Time { return now }
	b := NewBridge(cfg, clock, func(string) bool { return false }, liveStagingProc())

	mk := func(n int) report.Finding {
		f := eligibleFinding()
		dst := "9.9.9." + string(rune('0'+n)) + ":443"
		f.AutoMeta.Dst = dst
		f.AutoMeta.DetectedAt = now // event time tracks the (advancing) clock for G6
		f.Related = replaceRelated(f.Related, "dst=8.8.8.8:443", "dst="+dst)
		f.Related = replaceRelated(f.Related, "lineage: payload[c] ← bash[b] ← sshd[a]",
			"lineage: r"+string(rune('0'+n)))
		return f
	}

	// First emit consumes the single budget slot (a would-act, no throttle).
	out0 := b.Consider([]report.Finding{mk(0)})
	if len(shadowFindings(out0)) != 1 {
		t.Fatalf("first eligible finding should emit a would-act: %+v", out0)
	}

	throttleCount := func(out []report.Finding) int {
		n := 0
		for _, f := range out {
			if f.Check == checkThrottled {
				n++
			}
		}
		return n
	}

	// Subsequent over-budget attempts in the same window: throttle ONCE.
	got := 0
	for i := 1; i <= 5; i++ {
		got += throttleCount(b.Consider([]report.Finding{mk(i)}))
	}
	if got != 1 {
		t.Errorf("throttle must be emitted once per window, got %d in-window throttles", got)
	}

	// A new window reopens the throttle once.
	now = now.Add(cfg.RateWindow + time.Second)
	out := b.Consider([]report.Finding{mk(9)})
	// budget has reset, so this one is a would-act (not a throttle).
	if len(shadowFindings(out)) != 1 {
		t.Errorf("after the window resets, a fresh eligible finding should emit a would-act: %+v", out)
	}
}

// --- action-dedup on the STABLE key (resolved target + dst + lineage-root) ---

func TestActionDedupOnStableKey(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	f := eligibleFinding()
	first := shadowFindings(b.Consider([]report.Finding{f}))
	if len(first) != 1 {
		t.Fatalf("first decision should emit a would-act: %+v", first)
	}
	// Same resolved target + dst + lineage-root, even with a DIFFERENT (fresh /tmp)
	// Finding.Path → deduped to nothing.
	again := f
	again.Path = "/tmp/freshname-9999" // attacker rename-per-exec
	if out := shadowFindings(b.Consider([]report.Finding{again})); len(out) != 0 {
		t.Errorf("a repeat to the same stable target/dst/lineage must dedup: %+v", out)
	}
}

// FIX 3: a rename-per-exec /tmp storm — many findings with DISTINCT fresh /tmp
// names (distinct resolved target paths) but the SAME dst + lineage-root — must
// collapse to ONE auto-dedup unit. The dedup key excludes the volatile resolved
// path; keying on it (the old bug) would burn one unit per process and defeat the
// §4.5 #29 collapse.
func TestActionDedupCollapsesRenamePerExecStorm(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.RateMax = 100 // generous: prove DEDUP collapses the storm, not the rate budget
	// One Bridge, with a resolver that hands back a FRESH /tmp name on each call
	// (the rename-per-exec storm) while the dst (8.8.8.8:443) and lineage-root
	// (sshd[a]) — the stable dedup attributes — stay identical.
	var n int
	rotating := procFn(func(pid int) procInfo {
		n++
		return procInfo{Pid: pid, Exe: "/tmp/.x/payload-" + strconv.Itoa(n), UID: 1000, StartTime: 5000, Live: true}
	})
	b := newTestBridge(cfg, rotating)
	emitted := 0
	for i := 0; i < 20; i++ {
		emitted += len(shadowFindings(b.Consider([]report.Finding{eligibleFinding()})))
	}
	if emitted != 1 {
		t.Errorf("rename-per-exec storm (same dst+lineage-root) must collapse to 1 auto-unit, got %d", emitted)
	}
}

// FIX 2: a PID-reuse race — the live process at the captured PID has a DIFFERENT
// starttime than the one captured at correlation — must degrade to alert-only.
// PID is reusable; (Pid, StartTime) is the stable bind.
func TestG5StartTimeMismatchAlertOnly(t *testing.T) {
	// AutoMeta.StartTime is 5000 (eligibleFinding); the live proc reports 9999.
	proc := fakeProc{1337: {Exe: "/tmp/.x/payload", UID: 1000, StartTime: 9999, Live: true}}
	b := newTestBridge(baseAutoConfig(), proc)
	if out := shadowFindings(b.Consider([]report.Finding{eligibleFinding()})); len(out) != 0 {
		t.Errorf("a starttime mismatch (PID reuse) must be alert-only: %+v", out)
	}
}

// FIX 2: a captured StartTime of 0 means /proc was unreadable at capture time —
// we cannot identity-bind, so we fail closed to alert-only even if the live proc
// looks fine.
func TestG5ZeroCapturedStartTimeFailsClosed(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	f := eligibleFinding()
	f.AutoMeta.StartTime = 0
	if out := shadowFindings(b.Consider([]report.Finding{f})); len(out) != 0 {
		t.Errorf("a zero captured StartTime must fail the identity bind closed: %+v", out)
	}
}

// FIX 2: a captured exec_id that mismatches a resolver-supplied exec_id degrades
// to alert-only (the stronger bind when the resolver can supply exec_id).
func TestG5ExecIDMismatchAlertOnly(t *testing.T) {
	proc := fakeProc{1337: {Exe: "/tmp/.x/payload", UID: 1000, StartTime: 5000, ExecID: "different", Live: true}}
	b := newTestBridge(baseAutoConfig(), proc)
	if out := shadowFindings(b.Consider([]report.Finding{eligibleFinding()})); len(out) != 0 {
		t.Errorf("an exec_id mismatch must be alert-only: %+v", out)
	}
	// Matching exec_id + starttime passes.
	proc2 := fakeProc{1337: {Exe: "/tmp/.x/payload", UID: 1000, StartTime: 5000, ExecID: "c", Live: true}}
	b2 := newTestBridge(baseAutoConfig(), proc2)
	if out := shadowFindings(b2.Consider([]report.Finding{eligibleFinding()})); len(out) != 1 {
		t.Errorf("a matching exec_id + starttime must be eligible: %+v", out)
	}
}

// FIX 7: the shadow finding's dst AND the dedup key carry the ip:PORT, so the
// shadow matches the source finding and per-port dedup works. AutoMeta.Dst is the
// bare IP; the port comes from the dst= Related (or DstPort).
func TestShadowDstIncludesPort(t *testing.T) {
	b := newTestBridge(baseAutoConfig(), liveStagingProc())
	out := shadowFindings(b.Consider([]report.Finding{eligibleFinding()}))
	if len(out) != 1 {
		t.Fatalf("want 1 shadow finding, got %+v", out)
	}
	if got := relatedValue(out[0].Related, "dst="); got != "8.8.8.8:443" {
		t.Errorf("shadow dst=%q want ip:port 8.8.8.8:443", got)
	}

	// Per-port dedup: two findings to the SAME ip but DIFFERENT ports are distinct
	// decisions (distinct dedup keys), so both emit — the bare-IP key would have
	// wrongly collapsed them.
	b2 := newTestBridge(baseAutoConfig(), liveStagingProc())
	f1 := eligibleFinding()
	f1.AutoMeta.Dst, f1.AutoMeta.DstPort = "8.8.8.8", 443
	f1.Related = replaceRelated(f1.Related, "dst=8.8.8.8:443", "dst=8.8.8.8:443")
	f2 := eligibleFinding()
	f2.AutoMeta.Dst, f2.AutoMeta.DstPort = "8.8.8.8", 8443
	f2.Related = replaceRelated(f2.Related, "dst=8.8.8.8:443", "dst=8.8.8.8:8443")
	got := len(shadowFindings(b2.Consider([]report.Finding{f1})))
	got += len(shadowFindings(b2.Consider([]report.Finding{f2})))
	if got != 2 {
		t.Errorf("two distinct ports to the same IP must be 2 distinct decisions, got %d", got)
	}
}

// FIX 7: when AutoMeta carries only the bare IP + DstPort and there is no dst=
// Related, dstWithPort composes ip:port. (Belt-and-suspenders for the compose
// fallback path.)
func TestDstWithPortComposesFromAutoMeta(t *testing.T) {
	if got := dstWithPort(&report.AutoMeta{Dst: "8.8.8.8", DstPort: 443}, nil); got != "8.8.8.8:443" {
		t.Errorf("dstWithPort compose = %q want 8.8.8.8:443", got)
	}
	// dst= Related is preferred when present.
	if got := dstWithPort(&report.AutoMeta{Dst: "8.8.8.8", DstPort: 443}, []string{"dst=1.2.3.4:99"}); got != "1.2.3.4:99" {
		t.Errorf("dstWithPort should prefer dst= Related, got %q", got)
	}
	// bare IP with no port → bare IP.
	if got := dstWithPort(&report.AutoMeta{Dst: "8.8.8.8"}, nil); got != "8.8.8.8" {
		t.Errorf("dstWithPort bare IP = %q want 8.8.8.8", got)
	}
}

// --- ParseMode: canary/armed are not implemented → fatal-able error ---

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{"", ModeOff, false},
		{"off", ModeOff, false},
		{"dry-run", ModeDryRun, false},
		{"shadow", ModeShadow, false},
		{"canary", ModeShadow, true},
		{"armed", ModeShadow, true},
		{"armed:quarantine", ModeShadow, true},
		{"garbage", ModeOff, false}, // unparseable → off (fail-safe)
	}
	for _, tc := range cases {
		m, err := ParseMode(tc.in)
		if m != tc.want {
			t.Errorf("ParseMode(%q) mode=%v want %v", tc.in, m, tc.want)
		}
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseMode(%q) err=%v wantErr=%v", tc.in, err, tc.wantErr)
		}
	}
}

// --- concurrency: concurrent Consider calls are race-clean (run with -race) ---

func TestConsiderConcurrent(t *testing.T) {
	cfg := baseAutoConfig()
	cfg.RateMax = 1000 // generous so we exercise the emit path, not just throttle
	b := NewBridge(cfg, func() time.Time { return testNow }, func(string) bool { return false }, liveStagingProc())
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				f := eligibleFinding()
				dst := "8.8." + string(rune('0'+g)) + "." + string(rune('0'+(i%10))) + ":443"
				f.AutoMeta.Dst = dst
				f.Related = replaceRelated(f.Related, "dst=8.8.8.8:443", "dst="+dst)
				f.Related = replaceRelated(f.Related, "lineage: payload[c] ← bash[b] ← sshd[a]",
					"lineage: g"+string(rune('0'+g))+"i"+string(rune('0'+(i%10))))
				b.Consider([]report.Finding{f})
			}
		}(g)
	}
	wg.Wait()
}

// --- helpers to mutate Related slices in tests ---

func replaceRelated(related []string, old, new string) []string {
	out := make([]string, len(related))
	for i, r := range related {
		if r == old {
			out[i] = new
		} else {
			out[i] = r
		}
	}
	return out
}

func dropRelated(related []string, drop string) []string {
	var out []string
	for _, r := range related {
		if r != drop {
			out = append(out, r)
		}
	}
	return out
}
