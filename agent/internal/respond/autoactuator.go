package respond

import (
	"strconv"
	"strings"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// autoactuator.go is the ONE decision→execution wire built in this increment, and
// the ONLY new holder of a *Responder.
//
// ═══ SAFETY ARCHITECTURE (do not weaken) ═══
// The Bridge (auto.go) stays a PURE DECIDER: it holds no Executor/Responder and
// is structurally incapable of acting (TestBridgeHasNoExecutorField,
// TestBridgeNeverExecutesEvenWithEverythingConstructed). To feed the AutoActuator
// without giving the Bridge an actuator, the Bridge exposes a read-only accessor —
// ActionIntents — that RETURNS the eligible decision intents derived from the same
// decide() path and DOES NOT execute. The AutoActuator (a separate component,
// constructed only at the agent lifecycle layer in a LATER increment) consumes
// those Intents and is the only path from a decision to an action.
//
// ═══ RUNTIME-INERT IN THIS BUILD ═══
// The AutoActuator is NEVER constructed from main.go's runtime path: canary/armed
// are fatally refused at startup (armgate's deferredUnmet retains two unbuilt
// rails), so the runtime never reaches actuation and the Bridge stays shadow-only.
// The AutoActuator, GraceQueue and LockoutWatchdog are exercised ONLY by unit
// tests that inject a *Responder and force the mode.

// Intent is the read-only, derived description of an eligible would-action the
// Bridge selected. It is produced by Bridge.ActionIntents from the SAME decide()
// gate path the shadow finding uses — but it is a plain value the Bridge returns,
// NOT something the Bridge can act on. The AutoActuator turns an Intent into a
// Request only inside canary/armed (which only tests reach).
type Intent struct {
	// Action is the would-action class (currently only actionWouldQuarantine is
	// eligible; alert-only decisions never produce an Intent).
	Action string
	// Target is the resolved live /proc exe (G5), NEVER Finding.Path.
	Target string
	// Dst is the external destination (ip:port) the egress went to.
	Dst string
	// DryRunDefault is the per-action dry-run default (§4.4): TRUE unless the
	// operator explicitly armed THIS action. The AutoActuator honours it, so an
	// un-armed action never reaches the executor even in canary/armed.
	DryRunDefault bool
	// Inverse is the structured reverse Request that undoes the forward action
	// (§4.6) — an ActionUnquarantine carrying the quarantine origin, NEVER a shelled
	// string. Empty Action means the forward action has no inverse.
	Inverse Request
	// DedupKey is the stable per-action dedup key (dst|lineage-root) from decide().
	DedupKey string
	// pid/startTime/execID/stagingDirs are the identity bind the live, fd-based
	// quarantine Request (§3.2/§4.2) needs at execute time. Captured read-only at
	// decision time; carried so the forward Request re-binds to the SAME process.
	pid         int
	startTime   uint64
	execID      string
	stagingDirs []string
}

// forwardRequest builds the destructive forward Request for this Intent: the
// identity-bound, fd-based quarantine (§3.2/§4.2). It re-binds to the live process
// by (pid, starttime, exec_id) and constrains the target to the staging dirs, so
// the executor re-resolves /proc and refuses on any identity mismatch. dryRun sets
// the per-action §4.4 override.
func (it Intent) forwardRequest(dryRun bool) Request {
	dr := dryRun
	return Request{
		Action: ActionQuarantineFD,
		Target: strconv.Itoa(it.pid),
		Args: map[string]string{
			"starttime":    strconv.FormatUint(it.startTime, 10),
			"exec_id":      it.execID,
			"staging_dirs": strings.Join(it.stagingDirs, ","),
			"dst":          it.Dst,
		},
		Reason: "auto-response: would-quarantine fileless external-egress process",
		Actor:  "agentd-auto",
		DryRun: &dr,
	}
}

// ActionIntents runs the SAME §3.1 gates as Consider and returns the eligible
// would-action Intents — WITHOUT executing and WITHOUT emitting shadow findings.
// It is a READ-ONLY accessor: the Bridge still holds no actuator. A non-eligible
// (alert-only) decision yields no Intent. This is the seam the AutoActuator reads;
// the Bridge remains incapable of acting. Off mode yields nil.
func (b *Bridge) ActionIntents(findings []report.Finding) []Intent {
	if b.cfg.Mode == ModeOff {
		return nil
	}
	var out []Intent
	for _, f := range findings {
		dec := b.decide(f)
		if dec == nil || !dec.eligible {
			continue
		}
		out = append(out, b.intentFromDecision(*dec, f))
	}
	return out
}

// intentFromDecision projects a decided, eligible decision into a read-only
// Intent, including the structured inverse Request TEMPLATE. The inverse for a
// quarantine is a §4.6 ActionUnquarantine whose origin is the resolved target and
// whose Target (the quarantine destination) is deliberately LEFT EMPTY: it is
// unknown until the forward action runs. The GraceQueue fills it from the forward
// Result's structured QuarantineDst at veto time (M1), so the inverse is never
// addressable — and never runs — before the forward's real result exists.
func (b *Bridge) intentFromDecision(d decision, f report.Finding) Intent {
	var pid int
	var start uint64
	var exec string
	if f.AutoMeta != nil {
		pid = f.AutoMeta.Pid
		start = f.AutoMeta.StartTime
		exec = f.AutoMeta.ExecID
	}
	return Intent{
		Action:        d.wouldAction,
		Target:        d.target,
		Dst:           d.dst,
		DryRunDefault: true, // §4.4: dry-run unless THIS action is explicitly armed
		Inverse: Request{
			Action: ActionUnquarantine,
			Args:   map[string]string{"origin": d.target},
			Reason: "auto-undo: reverse of auto-quarantine",
			Actor:  "agentd-auto",
		},
		DedupKey:    d.dedupKey,
		pid:         pid,
		startTime:   start,
		execID:      exec,
		stagingDirs: append([]string(nil), b.cfg.StagingDirs...),
	}
}

// AutoActuator is the SINGLE decision→execution wire and the ONLY new holder of a
// *Responder. It turns a Bridge Intent into a guarded, grace-windowed, audited
// Request — but ONLY in canary/armed. In off/dry-run/shadow it is a pure no-op
// that returns the would-decision and NEVER calls the Responder's live Execute.
//
// It is constructed ONLY by unit tests in this build (canary/armed are refused at
// startup, so main.go's runtime path never builds one). The Bridge feeds it
// Intents via ActionIntents; the AutoActuator owns the Responder, the GraceQueue,
// and (optionally) the LockoutWatchdog.
type AutoActuator struct {
	resp  *Responder
	grace *GraceQueue
	// armed is the set of explicitly-armed action classes (§4.4). An action not in
	// this set keeps its dry-run default even in canary/armed — so a forgotten arm
	// flag never executes. nil/empty ⇒ nothing armed (everything dry-run).
	armed map[string]bool
	// watchdog is the optional §5 lockout watchdog. It is NOT driven from here in
	// this build (no runtime caller); it is held so a test can wire it.
	watchdog *LockoutWatchdog
}

// NewAutoActuator builds the wire over a Responder and a GraceQueue. armedActions
// is the §4.4 per-action arm set (action classes the operator explicitly armed
// LIVE); an action absent from it stays dry-run even in canary/armed. The
// Responder MUST be the only one the actuator ever calls.
//
// N1 (fail-closed): grace MUST be non-nil. A live forward with no veto window is a
// design violation (the operator would have no chance to CANCEL a destructive
// auto-action), so construction PANICS on a nil grace rather than silently
// permitting an un-windowed execute. resp must likewise be non-nil. (This is
// reached only by tests in this build; the panic is a loud, fail-closed guard.)
func NewAutoActuator(resp *Responder, grace *GraceQueue, armedActions []string) *AutoActuator {
	if resp == nil {
		panic("respond: NewAutoActuator requires a non-nil Responder")
	}
	if grace == nil {
		panic("respond: NewAutoActuator requires a non-nil GraceQueue (a live forward must always have a veto window; fail-closed)")
	}
	armed := make(map[string]bool, len(armedActions))
	for _, a := range armedActions {
		armed[a] = true
	}
	return &AutoActuator{resp: resp, grace: grace, armed: armed}
}

// WithWatchdog attaches a §5 lockout watchdog (held only; this build has no
// runtime caller that drives it). Returns the actuator for chaining.
func (a *AutoActuator) WithWatchdog(w *LockoutWatchdog) *AutoActuator {
	a.watchdog = w
	return a
}

// ActResult is what ActOn reports: whether the live Responder was reached, the
// effective dry-run mode, and the planned/actual Result (or a would-decision in a
// non-executing mode).
type ActResult struct {
	// Executed is true ONLY when the live Responder.Respond path ran (canary/armed,
	// armed action, grace expired). It is FALSE for every shadow/dry-run no-op.
	Executed bool
	// DryRun is the effective per-action dry-run mode the action would run in.
	DryRun bool
	// Result is the Responder Result when Executed, else a zero-value placeholder.
	Result Result
	// Detail explains a non-execution (mode shadow, dry-run default, grace pending).
	Detail string
}

// ActOn is the ONLY decision→execution path. Gate order (every gate fail-closed):
//
//  1. Mode: off/dry-run/shadow ⇒ NO-OP. Return the would-decision; the live
//     Responder is NEVER called. (This is the shadow guarantee.)
//  2. (canary/armed only) Per-action dry-run default (§4.4): the action runs
//     dry-run UNLESS its class was explicitly armed. A dry-run never executes.
//  3. Grace/veto window (§4): the action is enqueued; an operator CANCEL within the
//     window aborts it. ActOn returns "pending" — the actual execution happens when
//     the grace timer fires (the GraceQueue calls the Responder).
//  4. Execute: through the Responder (kill-switch, rate-limit, audit, guards all
//     enforced there).
//
// In this build only step 1's non-executing branch is ever reached at runtime
// (canary/armed are refused at startup); steps 2–4 are exercised only by tests.
func (a *AutoActuator) ActOn(it Intent, mode Mode) ActResult {
	// GATE 1 — Mode. off/dry-run/shadow NEVER reach the live Responder.
	if mode != ModeCanary && mode != ModeArmed {
		return ActResult{
			Executed: false,
			DryRun:   true,
			Detail:   "mode " + mode.String() + ": shadow-only, would " + it.Action + " " + it.Target + " (NOT executed)",
		}
	}

	// GATE 2 — Per-action dry-run default (§4.4). Dry-run unless THIS action class
	// was explicitly armed. Fail-closed: an empty arm set ⇒ everything dry-run.
	dryRun := it.DryRunDefault
	if a.armed[it.Action] {
		dryRun = false
	}
	if dryRun {
		// A dry-run forward Request flows through the Responder (which, being
		// dry-run, validates+audits and returns the plan WITHOUT calling Execute).
		res := a.resp.Respond(it.forwardRequest(true))
		return ActResult{Executed: false, DryRun: true, Result: res, Detail: "dry-run default (action not armed)"}
	}

	// GATE 3 — Grace/veto window (§4). The live action is HELD: the GraceQueue runs
	// it through the Responder when the timer fires, unless an operator CANCELs.
	//
	// N1 (fail-closed): a.grace is guaranteed non-nil by NewAutoActuator — a live
	// forward must ALWAYS have a veto window. If it is somehow nil (a hand-built
	// actuator that bypassed the constructor), REFUSE rather than execute an
	// un-windowed destructive action.
	if a.grace == nil {
		return ActResult{
			Executed: false,
			DryRun:   false,
			Detail:   "REFUSED: no grace/veto window configured — refusing to execute a forward auto-action with no operator CANCEL window (fail-closed)",
		}
	}
	// The inverse is enqueued as a TEMPLATE: its Action + origin arg are set, but its
	// Target (the quarantine destination) is intentionally EMPTY here — the grace
	// queue fills it from the forward Result's structured QuarantineDst at veto time
	// (M1), so the inverse can never run before/without the forward's real result.
	a.grace.Enqueue(graceItem{
		key:     it.Dst + "|" + it.Action + "|" + it.Target,
		forward: it.forwardRequest(false),
		inverse: it.Inverse,
	})
	return ActResult{Executed: false, DryRun: false, Detail: "enqueued in grace window (live execution deferred to grace expiry)"}
}
