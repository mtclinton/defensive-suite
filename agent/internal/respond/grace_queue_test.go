package respond

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// grace_queue_test.go exercises the §4 grace/veto window. The fake clock fires each
// armed callback ON ITS OWN GOROUTINE (not synchronously inline) so the real
// fire()↔Cancel synchronisation (statApplying → block-on-done) is exercised, not
// masked by a purely-synchronous stand-in (the review-flagged fixture). A second
// test uses a BLOCKING forward to deterministically interleave a veto with an
// in-flight forward and assert the inverse never starts first (M2).

// fakeGraceClock records every AfterFunc callback. fire() invokes a pending
// (un-stopped) callback on a SEPARATE goroutine — the deterministic stand-in for
// the grace window elapsing asynchronously. Stop() marks a timer stopped so a
// vetoed item never fires.
type fakeGraceClock struct {
	mu     sync.Mutex
	timers []*fakeGraceTimer
}

type fakeGraceTimer struct {
	mu      sync.Mutex
	fn      func()
	stopped bool
}

func (t *fakeGraceTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	already := t.stopped
	t.stopped = true
	return !already // true iff this call stopped it before it fired
}

func (c *fakeGraceClock) AfterFunc(_ time.Duration, f func()) graceTimer {
	t := &fakeGraceTimer{fn: f}
	c.mu.Lock()
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	return t
}

// fireAll invokes every armed-but-not-stopped callback exactly once, EACH ON ITS
// OWN GOROUTINE (the grace window elapsing asynchronously), and waits for them to
// return — modelling time.AfterFunc's real off-goroutine semantics while staying
// deterministic.
func (c *fakeGraceClock) fireAll() {
	c.mu.Lock()
	timers := append([]*fakeGraceTimer(nil), c.timers...)
	c.mu.Unlock()
	var wg sync.WaitGroup
	for _, t := range timers {
		t.mu.Lock()
		if t.stopped {
			t.mu.Unlock()
			continue
		}
		t.stopped = true
		fn := t.fn
		t.mu.Unlock()
		wg.Add(1)
		go func() { defer wg.Done(); fn() }()
	}
	wg.Wait()
}

// graceTestResponder builds a LIVE responder (dryRun=false) over a FakeExecutor so
// the grace queue's forward/inverse actually reach a recording executor.
func graceTestResponder() (*Responder, *FakeExecutor, *bytes.Buffer) {
	fake := &FakeExecutor{}
	buf := &bytes.Buffer{}
	r := NewResponder(fake, NewAuditLog(buf), false /* live */, graceGuards(), fixedClock())
	return r, fake, buf
}

// graceGuards permits the fd-quarantine + unquarantine round-trip used in tests.
func graceGuards() Guards {
	g := DefaultGuards()
	g.QuarantineDir = "/var/lib/agentd/quarantine"
	return g
}

// realInverseGraceItem builds the held item from the ACTUAL Bridge-derived Intent
// (intentFromDecision): a forward quarantine and a §4.6 inverse TEMPLATE whose
// Target is EMPTY (the destination is unknown until the forward runs). This
// exercises the real path the review flagged as masked by a hand-built valid
// inverse Target.
func realInverseGraceItem(t *testing.T) graceItem {
	t.Helper()
	it := eligibleIntent(t) // the real Intent the Bridge derives
	if it.Inverse.Target != "" {
		t.Fatalf("the real inverse TEMPLATE must carry NO Target (filled from the forward Result), got %q", it.Inverse.Target)
	}
	if it.Inverse.Action != ActionUnquarantine || it.Inverse.arg("origin") != "/tmp/.x/payload" {
		t.Fatalf("the real inverse must be a structured unquarantine with the origin, got %+v", it.Inverse)
	}
	return graceItem{
		key:     it.Dst + "|" + it.Action + "|" + it.Target,
		forward: it.forwardRequest(false),
		inverse: it.Inverse,
	}
}

// TestGraceVetoExpiryAllows: with NO veto, the grace window elapsing APPLIES the
// forward action through the Responder exactly once.
func TestGraceVetoExpiryAllows(t *testing.T) {
	r, fake, _ := graceTestResponder()
	clk := &fakeGraceClock{}
	q := NewGraceQueue(r, time.Minute, clk)

	q.Enqueue(realInverseGraceItem(t))
	if fake.CallCount() != 0 {
		t.Fatalf("nothing should execute before grace expiry, got %d calls", fake.CallCount())
	}

	clk.fireAll() // grace window elapses with no veto

	if fake.CallCount() != 1 {
		t.Fatalf("grace expiry should apply the forward action once, got %d", fake.CallCount())
	}
	if last, _ := fake.Last(); last.Action != ActionQuarantineFD {
		t.Errorf("expiry should have applied the forward quarantine, got %q", last.Action)
	}
	if len(q.CriticalFindings()) != 0 {
		t.Errorf("a clean expiry should emit no CRITICAL findings: %v", q.CriticalFindings())
	}
}

// TestGraceVetoCancelInvokesRealInverse: the REAL intentFromDecision inverse, run
// through GraceQueue.Cancel AFTER the forward applied, reverses successfully —
// Cancel returns true and emits NO CRITICAL. This is the M1 acceptance test: a
// quarantine veto CAN reverse (the inverse Target is filled from the forward
// Result's structured QuarantineDst, not left empty).
func TestGraceVetoCancelInvokesRealInverse(t *testing.T) {
	r, fake, _ := graceTestResponder()
	clk := &fakeGraceClock{}
	q := NewGraceQueue(r, time.Minute, clk)

	item := realInverseGraceItem(t)
	q.Enqueue(item)
	clk.fireAll() // forward APPLIED
	if fake.CallCount() != 1 {
		t.Fatalf("forward should be applied on expiry, got %d", fake.CallCount())
	}

	// Operator veto AFTER application → run the REAL inverse. With the structured
	// QuarantineDst now wired, the reversal succeeds.
	if landed := q.Cancel(item.key); !landed {
		t.Fatal("a veto whose REAL inverse SUCCEEDS must report landed=true (M1: quarantine veto can reverse)")
	}
	if fake.CallCount() != 2 {
		t.Fatalf("a post-apply veto should run the inverse (2 total calls), got %d", fake.CallCount())
	}
	last, _ := fake.Last()
	if last.Action != ActionUnquarantine || last.arg("origin") != "/tmp/.x/payload" {
		t.Errorf("veto should run the structured unquarantine inverse, got %+v", last)
	}
	// The inverse Target must have been filled from the forward Result's structured
	// QuarantineDst (the FakeExecutor returns a deterministic fake dst).
	if last.Target == "" {
		t.Error("the inverse Target must be filled from the forward Result's QuarantineDst, was empty")
	}
	if len(q.CriticalFindings()) != 0 {
		t.Errorf("a SUCCESSFUL inverse must not emit CRITICAL: %v", q.CriticalFindings())
	}
}

// A PRE-application veto (within the window, before expiry) stops the timer and
// runs NOTHING — the forward never executed, so there is nothing to reverse.
func TestGraceVetoPreApplicationStopsForward(t *testing.T) {
	r, fake, _ := graceTestResponder()
	clk := &fakeGraceClock{}
	q := NewGraceQueue(r, time.Minute, clk)

	item := realInverseGraceItem(t)
	q.Enqueue(item)
	if landed := q.Cancel(item.key); !landed {
		t.Fatal("pre-expiry Cancel should land")
	}
	// The timer is now stopped; firing the (stopped) timer must be a no-op.
	clk.fireAll()
	if fake.CallCount() != 0 {
		t.Fatalf("a pre-application veto must execute neither forward nor inverse, got %d", fake.CallCount())
	}
	if q.Pending() != 0 {
		t.Errorf("a vetoed item should be removed, pending=%d", q.Pending())
	}
}

// TestGraceConcurrentVetoNeverPrecedesForward is the M2 race test: a veto that
// arrives WHILE the forward is in flight must BLOCK until the forward finishes,
// then run the inverse — the inverse can never start before the forward. We use a
// blocking forward executor so the interleaving is deterministic: the test releases
// the forward only after confirming the Cancel goroutine is already blocked, then
// asserts the executor saw the forward FIRST and the inverse SECOND.
func TestGraceConcurrentVetoNeverPrecedesForward(t *testing.T) {
	forwardEntered := make(chan struct{})
	releaseForward := make(chan struct{})
	var order []string
	var omu sync.Mutex
	record := func(s string) { omu.Lock(); order = append(order, s); omu.Unlock() }

	fake := &FakeExecutor{ResultFn: func(req Request) Result {
		if req.Action == ActionQuarantineFD {
			close(forwardEntered) // signal the forward is executing
			<-releaseForward      // hold it open so the veto races it
			record("forward")
			return Result{OK: true, Action: req.Action, Target: req.Target, QuarantineDst: "/var/lib/agentd/quarantine/blk-payload"}
		}
		record("inverse")
		return Result{OK: true, Action: req.Action, Target: req.Target}
	}}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), false, graceGuards(), fixedClock())
	clk := &fakeGraceClock{}
	q := NewGraceQueue(r, time.Minute, clk)

	item := realInverseGraceItem(t)
	q.Enqueue(item)

	// Fire the forward on its own goroutine (it will block inside the executor).
	go clk.fireAll()
	<-forwardEntered // the forward is now IN FLIGHT (statApplying)

	// Issue the veto while the forward is held open. Cancel must BLOCK on done.
	cancelLanded := make(chan bool, 1)
	go func() { cancelLanded <- q.Cancel(item.key) }()

	// Give the Cancel goroutine time to reach its block; the inverse must NOT have
	// run yet (the forward is still held).
	time.Sleep(20 * time.Millisecond)
	omu.Lock()
	if len(order) != 0 {
		omu.Unlock()
		t.Fatalf("nothing should have executed while the forward is held; order=%v", order)
	}
	omu.Unlock()

	// Release the forward; the blocked Cancel then runs the inverse.
	close(releaseForward)
	if landed := <-cancelLanded; !landed {
		t.Fatal("the post-apply veto should land (inverse succeeds)")
	}

	omu.Lock()
	defer omu.Unlock()
	if len(order) != 2 || order[0] != "forward" || order[1] != "inverse" {
		t.Fatalf("the inverse must run STRICTLY AFTER the forward; got order=%v", order)
	}
}

// TestGraceVetoInverseFailureAlerts: a veto whose inverse FAILS audits loudly,
// emits a CRITICAL finding, and reports landed=FALSE (never silently assumes
// reversibility).
func TestGraceVetoInverseFailureAlerts(t *testing.T) {
	fake := &FakeExecutor{Err: errors.New("inverse exec failed")} // every Execute fails
	buf := &bytes.Buffer{}
	r := NewResponder(fake, NewAuditLog(buf), false /* live */, graceGuards(), fixedClock())
	clk := &fakeGraceClock{}
	q := NewGraceQueue(r, time.Minute, clk)

	item := realInverseGraceItem(t)
	q.Enqueue(item)
	clk.fireAll() // forward "applied" (the executor failed, but the queue marked it applied)

	if landed := q.Cancel(item.key); landed {
		t.Fatal("a veto whose inverse FAILS must report landed=false (the reversal did not succeed)")
	}
	crit := q.CriticalFindings()
	if len(crit) != 1 {
		t.Fatalf("a failed inverse must emit exactly one CRITICAL finding, got %d", len(crit))
	}
	if crit[0].Severity != report.SeverityCritical {
		t.Errorf("the alert must be CRITICAL severity, got %v", crit[0].Severity)
	}
	if !bytes.Contains(buf.Bytes(), []byte("GRACE VETO INVERSE FAILED")) {
		t.Errorf("a failed inverse must write a LOUD audit line; audit=%s", buf.String())
	}
}

// An inverse with NO Action (irreversible forward, e.g. kill) is treated as a
// failed reversal: CRITICAL + loud, landed=false, never silent.
func TestGraceVetoIrreversibleForwardAlerts(t *testing.T) {
	r, _, _ := graceTestResponder()
	clk := &fakeGraceClock{}
	q := NewGraceQueue(r, time.Minute, clk)

	item := graceItem{
		key:     "k|kill|1337",
		forward: Request{Action: ActionKill, Target: "1337"},
		inverse: Request{}, // no inverse — kill is irreversible
	}
	q.Enqueue(item)
	clk.fireAll()
	if landed := q.Cancel(item.key); landed {
		t.Error("vetoing an irreversible applied action must report landed=false")
	}
	if len(q.CriticalFindings()) != 1 {
		t.Fatalf("vetoing an irreversible applied action must emit CRITICAL, got %d", len(q.CriticalFindings()))
	}
}

// A forward Result with NO structured QuarantineDst (the executor did not report a
// destination) leaves the inverse un-addressable: the veto must fail-closed (CRITICAL,
// landed=false) rather than guess a Target.
func TestGraceVetoMissingDstFailsClosed(t *testing.T) {
	fake := &FakeExecutor{ResultFn: func(req Request) Result {
		// Forward "succeeds" but reports NO QuarantineDst.
		return Result{OK: true, Action: req.Action, Target: req.Target}
	}}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), false, graceGuards(), fixedClock())
	clk := &fakeGraceClock{}
	q := NewGraceQueue(r, time.Minute, clk)

	item := realInverseGraceItem(t)
	q.Enqueue(item)
	clk.fireAll()
	if landed := q.Cancel(item.key); landed {
		t.Error("a veto with no structured destination must fail-closed (landed=false)")
	}
	if len(q.CriticalFindings()) != 1 {
		t.Fatalf("a missing-destination veto must emit CRITICAL, got %d", len(q.CriticalFindings()))
	}
}

// Cancel of an UNKNOWN key reports no veto landed and does nothing.
func TestGraceCancelUnknownKeyNoOp(t *testing.T) {
	r, fake, _ := graceTestResponder()
	q := NewGraceQueue(r, time.Minute, &fakeGraceClock{})
	if landed := q.Cancel("nope"); landed {
		t.Error("Cancel of an unknown key must report no veto landed")
	}
	if fake.CallCount() != 0 {
		t.Errorf("Cancel of an unknown key must not execute anything, got %d", fake.CallCount())
	}
}
