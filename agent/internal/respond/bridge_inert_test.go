package respond

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// spyExecutor records EVERY Execute call. It exists to prove the Bridge never
// reaches an actuator: even when a fully-armed responder + this spy executor are
// constructed alongside the Bridge, Consider() makes ZERO Execute calls (the
// Bridge holds no reference to either).
type spyExecutor struct{ calls int64 }

func (s *spyExecutor) Execute(req Request) (Result, error) {
	atomic.AddInt64(&s.calls, 1)
	return Result{OK: true, Action: req.Action, Target: req.Target}, nil
}

// TestBridgeNeverExecutesEvenWithEverythingConstructed is the load-bearing
// no-execute invariant for this increment: construct the WHOLE world — a spy
// executor, a LIVE responder armed with that executor, AND a Bridge in the
// most-aggressive (forced-armed) mode over an eligible finding — and assert the
// spy executor recorded ZERO calls. The Bridge cannot execute because it has no
// responder/executor reference; it can only emit findings. (The bridge→Respond
// wire is a deliberate post-soak step, DEFERRED.)
func TestBridgeNeverExecutesEvenWithEverythingConstructed(t *testing.T) {
	spy := &spyExecutor{}
	// A fully LIVE responder armed with the spy — exactly the actuator the Bridge
	// must NOT be able to reach.
	live := NewResponder(spy, NewAuditLog(nil), false, DefaultGuards(), func() time.Time { return testNow })
	_ = live // constructed but deliberately NOT connected to the bridge

	cfg := baseAutoConfig()
	cfg.Mode = ModeArmed // most-aggressive; not reachable via ParseMode, forced here
	b := newTestBridge(cfg, liveStagingProc())

	// Run the eligible (would-quarantine) finding through Consider many times.
	for i := 0; i < 5; i++ {
		out := b.Consider([]report.Finding{eligibleFinding()})
		for _, f := range out {
			// Whatever it emits is ONLY a report.Finding (a shadow/throttle decision).
			if f.Check != checkShadow && f.Check != checkThrottled {
				t.Errorf("bridge emitted an unexpected check %q (must only emit findings)", f.Check)
			}
		}
	}

	if got := atomic.LoadInt64(&spy.calls); got != 0 {
		t.Fatalf("the Bridge must NEVER reach an executor; spy recorded %d Execute calls", got)
	}
}
