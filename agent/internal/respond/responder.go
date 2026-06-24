package respond

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Responder is the manual-response orchestrator. It is deliberately
// dry-run-by-default: a zero-value-ish Responder built without flipping DryRun
// off will never call the Executor. The agent's config (ResponseEnabled, default
// false) is the only thing that sets DryRun=false.
//
// Respond's pipeline is: Validate (pure guards) → KILL-SWITCH check → RATE-LIMIT
// (live only) → audit the intent → if DryRun, return the planned Result WITHOUT
// calling Execute → else Execute → audit the result.
//
// The two BRAKES (kill-switch + rate limit) sit on the weaponizable primitive:
// even with response armed, an operator can instantly disarm everything by
// touching the kill-switch file, and a hijacked surface cannot turn into a rapid
// mass-action because the rate limit caps live executions per window.
type Responder struct {
	Exec   Executor
	Audit  *AuditLog
	DryRun bool
	Guards Guards
	now    func() time.Time

	// KillSwitchPath, when non-empty and the file EXISTS, globally disarms ALL
	// response (live and dry-run alike). Checked on every Respond.
	KillSwitchPath string
	// fileExists checks whether KillSwitchPath exists. Injectable for tests;
	// defaults to an os.Stat-based check.
	fileExists func(string) bool

	// rate limits LIVE executions (nil = unlimited). Only the live path consumes
	// from it; dry-run is free.
	rate *rateLimiter
}

// NewResponder builds a Responder. DryRun defaults to TRUE here: the only way to
// get a live responder is to pass dryRun=false explicitly (the agent does that
// only when ResponseEnabled is set). A nil clock falls back to time.Now.
//
// The brakes are configured AFTER construction via WithKillSwitch / WithRateLimit
// so existing callers/tests keep their two-gate behaviour unchanged.
func NewResponder(exec Executor, audit *AuditLog, dryRun bool, guards Guards, now func() time.Time) *Responder {
	if now == nil {
		now = time.Now
	}
	return &Responder{
		Exec:       exec,
		Audit:      audit,
		DryRun:     dryRun,
		Guards:     guards,
		now:        now,
		fileExists: statExists,
	}
}

// WithKillSwitch arms the global kill-switch at path. While that file exists,
// every Respond is refused (regardless of DryRun). An empty path disables the
// check. exists is the existence probe; nil uses the default os.Stat-based one
// (tests inject a deterministic func). Returns the Responder for chaining.
func (r *Responder) WithKillSwitch(path string, exists func(string) bool) *Responder {
	r.KillSwitchPath = path
	if exists != nil {
		r.fileExists = exists
	} else if r.fileExists == nil {
		r.fileExists = statExists
	}
	return r
}

// WithRateLimit caps LIVE executions to max per window (sliding window driven by
// the Responder's injected clock). max<=0 or window<=0 disables the limit.
// Dry-run is never counted. Returns the Responder for chaining.
func (r *Responder) WithRateLimit(max int, window time.Duration) *Responder {
	if max > 0 && window > 0 {
		r.rate = &rateLimiter{max: max, window: window}
	} else {
		r.rate = nil
	}
	return r
}

// statExists is the default kill-switch probe: the file exists iff os.Stat
// succeeds. A non-IsNotExist error (e.g. a permission problem reaching the path)
// is treated as "exists" — failing SAFE: if we can't prove the kill-switch is
// absent, we behave as though response is disabled.
func statExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

// rateLimiter is a sliding-window limiter over the Responder's injected clock. It
// records the timestamps of recent live executions and refuses once max events
// fall within the trailing window.
type rateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	events []time.Time
}

// allow reports whether an execution at time now is within budget, recording it
// when allowed. Timestamps older than the window are pruned first, so it is a
// true sliding window. Not consuming on refusal means a blocked storm cannot
// extend its own lockout.
func (rl *rateLimiter) allow(now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := now.Add(-rl.window)
	kept := rl.events[:0]
	for _, t := range rl.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	rl.events = kept
	if len(rl.events) >= rl.max {
		return false
	}
	rl.events = append(rl.events, now)
	return true
}

// Respond validates, audits, and (unless dry-run) executes req. It never returns
// an error: a refusal or executor failure is reported as a Result with OK=false
// and a Detail, so the HTTP layer can always render a Result to the operator.
//
// §4.4 per-action arming: the effective dry-run mode is req.DryRun when the
// request sets it, else the Responder-level r.DryRun. The brake order is
// UNCHANGED — Validate → kill-switch → rate-limit → audit → execute — and a
// per-action-LIVE request still passes through every brake (the kill-switch and
// rate-limit both apply to it). When req.DryRun is unset (the manual socket never
// sets it) behaviour is byte-for-byte identical to before.
func (r *Responder) Respond(req Request) Result {
	now := r.clock()
	dryRun := req.dryRun(r.DryRun)

	// 1. Guardrails (pure). A refusal is audited as a failed result and returned;
	//    the executor is never reached.
	if err := r.Guards.Validate(req); err != nil {
		res := Result{
			OK:     false,
			Action: req.Action,
			Target: req.Target,
			DryRun: dryRun,
			Detail: "refused: " + err.Error(),
		}
		_ = r.Audit.Intent(now, req, dryRun)
		_ = r.Audit.Result(now, req, res)
		return res
	}

	// 2. KILL-SWITCH: a global, file-backed disarm. If the kill-switch file exists,
	//    REFUSE the action regardless of DryRun — an operator can `touch` it to
	//    instantly disable ALL response without restarting agentd. Checked on every
	//    request, BEFORE the intent audit, so the refusal is what gets recorded and
	//    the executor is never reached even when live. The §4.4 per-action-live path
	//    is NOT exempt: a per-Request live action is still refused here.
	if r.KillSwitchPath != "" && r.fileExists != nil && r.fileExists(r.KillSwitchPath) {
		res := r.refuse(req, dryRun, fmt.Sprintf("response globally disabled (kill-switch %s)", r.KillSwitchPath))
		_ = r.Audit.Intent(now, req, dryRun)
		_ = r.Audit.Result(now, req, res)
		return res
	}

	// 3. RATE LIMIT: cap LIVE executions per window so a hijacked surface cannot
	//    become a rapid mass-kill / mass-isolate DoS. Dry-run is FREE (never
	//    counted) — only the live path consumes from the limiter. Refused requests
	//    do not consume budget, so a blocked storm cannot extend its own lockout.
	//    The §4.4 per-action-live path consumes the SAME limiter (the only shared
	//    mutable in respond/), so a per-action-live action is rate-limited too.
	if !dryRun && r.rate != nil && !r.rate.allow(now) {
		res := r.refuse(req, dryRun, fmt.Sprintf("rate limit exceeded (%d per %s)", r.rate.max, r.rate.window))
		_ = r.Audit.Intent(now, req, dryRun)
		_ = r.Audit.Result(now, req, res)
		return res
	}

	// 4. Audit the intent BEFORE doing anything.
	_ = r.Audit.Intent(now, req, dryRun)

	// 5. Dry-run: return the planned action and audit it. Execute is NOT called.
	if dryRun {
		res := Result{
			OK:     true,
			Action: req.Action,
			Target: req.Target,
			DryRun: true,
			Detail: "dry-run: would " + planned(req),
			Undo:   plannedUndo(req),
		}
		_ = r.Audit.Result(r.clock(), req, res)
		return res
	}

	// 6. Live path: execute and audit the real outcome.
	res, err := r.Exec.Execute(req)
	res.Action, res.Target, res.DryRun = req.Action, req.Target, false
	if err != nil {
		res.OK = false
		if res.Detail == "" {
			res.Detail = "execute failed: " + err.Error()
		} else {
			res.Detail += " (error: " + err.Error() + ")"
		}
	}
	_ = r.Audit.Result(r.clock(), req, res)
	return res
}

// isReverseAction reports whether action is one of the §4.6 REVERSE (un-contain)
// actuators. Only these are eligible for the kill/rate-EXEMPT rescue path
// (RespondRescue) — a forward containment action is never exempt.
func isReverseAction(action string) bool {
	switch action {
	case ActionUnquarantine, ActionDeIsolate, ActionRestoreKey:
		return true
	default:
		return false
	}
}

// RespondRescue is the §4.3/§5 OPERATOR-RESCUE entrypoint for the lockout
// watchdog's auto-undo. It runs a REVERSE action (Unquarantine/DeIsolate/
// RestoreKey) BYPASSING BOTH the kill-switch AND the rate limiter, because §4.3/§5
// decouples auto-undo from the kill-switch and the rate budget: the operator must
// ALWAYS be un-lockable. The kill-switch stops FORWARD auto-actions, never the
// operator-rescue un-contain; and the rate budget (exhausted by the preceding
// containment burst) must not silently defeat the rescue.
//
// SAFETY (why this is not a hole): the bypass is SCOPED to reverse actions only.
// RespondRescue REFUSES any non-reverse (forward/containment) action, so it can
// never be used to run a kill/isolate/quarantine around the brakes. Forward
// actions keep using Respond, where the kill-switch + rate limit still apply. The
// reverse action still flows through Validate (pure guards) and the full audit
// (intent + result), so it is attributable; only the two BRAKES are skipped.
func (r *Responder) RespondRescue(req Request) Result {
	now := r.clock()
	dryRun := req.dryRun(r.DryRun)

	// Scope the bypass: REFUSE a non-reverse action so the exempt path can never run
	// a forward/containment action around the brakes.
	if !isReverseAction(req.Action) {
		res := r.refuse(req, dryRun, fmt.Sprintf("rescue path refuses non-reverse action %q (rescue is reverse-only: unquarantine/de-isolate/restore-key)", req.Action))
		_ = r.Audit.Intent(now, req, dryRun)
		_ = r.Audit.Result(now, req, res)
		return res
	}

	// 1. Guardrails (pure) — still enforced; a refused reverse action is audited.
	if err := r.Guards.Validate(req); err != nil {
		res := Result{
			OK:     false,
			Action: req.Action,
			Target: req.Target,
			DryRun: dryRun,
			Detail: "refused: " + err.Error(),
		}
		_ = r.Audit.Intent(now, req, dryRun)
		_ = r.Audit.Result(now, req, res)
		return res
	}

	// NOTE: NO kill-switch check and NO rate-limit consumption here — the deliberate
	// §4.3/§5 decision (the operator must always be un-lockable).

	// 2. Audit the intent BEFORE acting.
	_ = r.Audit.Intent(now, req, dryRun)

	// 3. Dry-run: return the plan, do not Execute (mirrors Respond).
	if dryRun {
		res := Result{
			OK:     true,
			Action: req.Action,
			Target: req.Target,
			DryRun: true,
			Detail: "dry-run: would " + planned(req),
			Undo:   plannedUndo(req),
		}
		_ = r.Audit.Result(r.clock(), req, res)
		return res
	}

	// 4. Live: execute and audit the real outcome.
	res, err := r.Exec.Execute(req)
	res.Action, res.Target, res.DryRun = req.Action, req.Target, false
	if err != nil {
		res.OK = false
		if res.Detail == "" {
			res.Detail = "execute failed: " + err.Error()
		} else {
			res.Detail += " (error: " + err.Error() + ")"
		}
	}
	_ = r.Audit.Result(r.clock(), req, res)
	return res
}

// refuse builds a not-OK Result for a brake (kill-switch / rate limit) refusal,
// carrying the EFFECTIVE dry-run flag (§4.4) so the audit reflects the live/dry
// mode the request would have run in.
func (r *Responder) refuse(req Request, dryRun bool, detail string) Result {
	return Result{
		OK:     false,
		Action: req.Action,
		Target: req.Target,
		DryRun: dryRun,
		Detail: detail,
	}
}

func (r *Responder) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// planned is a human-readable description of the action a live Respond would take
// — shown to the operator in dry-run so they can see exactly what they're about
// to authorize.
func planned(req Request) string {
	switch req.Action {
	case ActionKill:
		return "SIGKILL pid " + req.Target
	case ActionIsolate:
		return "install nftables egress-drop except interface " + req.Target
	case ActionQuarantine:
		return "move " + req.Target + " to the quarantine dir (chattr +i, chmod 000)"
	case ActionQuarantineFD:
		return "identity-bind to the live process, then quarantine its open exe BY FD (O_NOFOLLOW)"
	case ActionRevokeKey:
		return "remove the authorized_keys line matching fingerprint from " + req.Target
	case ActionBlockHash:
		return "add a fapolicyd deny rule for sha256 " + req.Target
	case ActionUnquarantine:
		return "chattr -i " + req.Target + " && mv it back to " + req.arg("origin")
	case ActionDeIsolate:
		return "nft delete table inet dsuite_isolate (lift the egress isolation)"
	case ActionRestoreKey:
		return "restore " + req.Target + " from its .dsuite.bak backup"
	default:
		return req.String()
	}
}

// plannedUndo mirrors the executor's Undo string for the actions that are
// reversible, so dry-run shows the operator how the action would be undone.
func plannedUndo(req Request) string {
	switch req.Action {
	case ActionKill:
		return "" // irreversible
	case ActionIsolate:
		return "nft delete table inet dsuite_isolate"
	case ActionQuarantine, ActionQuarantineFD:
		// The structured inverse is an ActionUnquarantine Request (§4.6), not this
		// free-text string; this string is the human-readable note shown in dry-run.
		return "chattr -i <quarantined> && mv <quarantined> " + req.Target + " (or: an unquarantine Request)"
	case ActionRevokeKey:
		return "restore " + req.Target + " from its .dsuite.bak backup (or: a restore-key Request)"
	case ActionBlockHash:
		return "remove the fapolicyd deny rule and reload"
	case ActionUnquarantine, ActionDeIsolate, ActionRestoreKey:
		// These ARE the inverses; their own undo is to re-apply the forward action,
		// which is not auto-derivable here.
		return ""
	default:
		return ""
	}
}
