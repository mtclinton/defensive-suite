package respond

import (
	"reflect"
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

// forbiddenActuatorType reports whether t is (or transitively contains) a type that
// would let a "pure decider" value smuggle an actuator/side-effecting handle:
// *Responder / Executor / *RealExecutor / *FakeExecutor, any func, *os.File, or a
// raw uintptr. It walks pointers, slices, arrays, maps, and (one level of) struct
// fields so the seam cannot hide an actuator inside a nested value.
func forbiddenActuatorType(t reflect.Type, depth int) (string, bool) {
	if t == nil || depth < 0 {
		return "", false
	}
	switch t.String() {
	case "*respond.Responder", "respond.Responder",
		"respond.Executor",
		"*respond.RealExecutor", "*respond.FakeExecutor",
		"*os.File", "os.File",
		"uintptr":
		return t.String(), true
	}
	switch t.Kind() {
	case reflect.Func:
		// A func field/return could close over a Responder and execute — forbidden on
		// the read-only Intent/Bridge seam.
		return "func (" + t.String() + ")", true
	case reflect.Uintptr, reflect.UnsafePointer:
		return t.String(), true
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Chan, reflect.Map:
		if name, bad := forbiddenActuatorType(t.Elem(), depth-1); bad {
			return name, true
		}
		if t.Kind() == reflect.Map {
			if name, bad := forbiddenActuatorType(t.Key(), depth-1); bad {
				return name, true
			}
		}
	case reflect.Struct:
		// Don't descend into report.Request etc. infinitely; one level under the seam
		// is enough to catch a directly-embedded actuator. report.Finding / Request are
		// plain data and safe.
		for i := 0; i < t.NumField(); i++ {
			if name, bad := forbiddenActuatorType(t.Field(i).Type, depth-1); bad {
				return name + " (in " + t.String() + "." + t.Field(i).Name + ")", true
			}
		}
	}
	return "", false
}

// TestIntentAndBridgeSeamHoldNoActuator (N3) extends the structural purity pin to
// the NEW ActionIntents/Intent seam: it reflects over EVERY field of Intent{} AND
// over *Bridge's whole method set (params + returns), rejecting any field/return
// whose type is *Responder / Executor / *RealExecutor / a func / *os.File / uintptr.
// This closes the gap left by TestBridgeHasNoExecutorField (which only inspected the
// Bridge's own fields): the read-only Intent the Bridge now returns, and the
// signatures of every Bridge method, are likewise incapable of carrying an actuator.
func TestIntentAndBridgeSeamHoldNoActuator(t *testing.T) {
	// (a) Every field of the read-only Intent must be plain data — no actuator handle.
	it := reflect.TypeOf(Intent{})
	for i := 0; i < it.NumField(); i++ {
		f := it.Field(i)
		if name, bad := forbiddenActuatorType(f.Type, 4); bad {
			t.Fatalf("Intent.%s carries a forbidden actuator type %s — the read-only seam must hold no actuator", f.Name, name)
		}
	}

	// (b) Every method of *Bridge: its parameters AND returns must hold no actuator.
	// (ActionIntents returns []Intent; none of the Bridge's methods may take or
	// return a *Responder/Executor/func/file, so the decision engine cannot be handed
	// one through any method signature.)
	bt := reflect.TypeOf((*Bridge)(nil))
	for i := 0; i < bt.NumMethod(); i++ {
		m := bt.Method(i)
		mt := m.Type
		for j := 1; j < mt.NumIn(); j++ { // j=0 is the *Bridge receiver
			if name, bad := forbiddenActuatorType(mt.In(j), 4); bad {
				t.Fatalf("(*Bridge).%s takes a forbidden actuator type %s in arg %d", m.Name, name, j)
			}
		}
		for j := 0; j < mt.NumOut(); j++ {
			if name, bad := forbiddenActuatorType(mt.Out(j), 4); bad {
				t.Fatalf("(*Bridge).%s returns a forbidden actuator type %s (return %d)", m.Name, name, j)
			}
		}
	}

	// Sanity: the detector actually FIRES on a known-bad type (so a green test is
	// meaningful, not a no-op).
	if _, bad := forbiddenActuatorType(reflect.TypeOf((*Responder)(nil)), 4); !bad {
		t.Fatal("the actuator-type detector must flag *Responder (otherwise the pin is a no-op)")
	}
	if _, bad := forbiddenActuatorType(reflect.TypeOf(struct{ R *Responder }{}), 4); !bad {
		t.Fatal("the detector must flag a *Responder NESTED in a struct")
	}
}
