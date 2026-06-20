package respond

import "time"

// Responder is the manual-response orchestrator. It is deliberately
// dry-run-by-default: a zero-value-ish Responder built without flipping DryRun
// off will never call the Executor. The agent's config (ResponseEnabled, default
// false) is the only thing that sets DryRun=false.
//
// Respond's pipeline is: Validate (pure guards) → audit the intent → if DryRun,
// return the planned Result WITHOUT calling Execute → else Execute → audit the
// result.
type Responder struct {
	Exec   Executor
	Audit  *AuditLog
	DryRun bool
	Guards Guards
	now    func() time.Time
}

// NewResponder builds a Responder. DryRun defaults to TRUE here: the only way to
// get a live responder is to pass dryRun=false explicitly (the agent does that
// only when ResponseEnabled is set). A nil clock falls back to time.Now.
func NewResponder(exec Executor, audit *AuditLog, dryRun bool, guards Guards, now func() time.Time) *Responder {
	if now == nil {
		now = time.Now
	}
	return &Responder{
		Exec:   exec,
		Audit:  audit,
		DryRun: dryRun,
		Guards: guards,
		now:    now,
	}
}

// Respond validates, audits, and (unless dry-run) executes req. It never returns
// an error: a refusal or executor failure is reported as a Result with OK=false
// and a Detail, so the HTTP layer can always render a Result to the operator.
func (r *Responder) Respond(req Request) Result {
	now := r.clock()

	// 1. Guardrails (pure). A refusal is audited as a failed result and returned;
	//    the executor is never reached.
	if err := r.Guards.Validate(req); err != nil {
		res := Result{
			OK:     false,
			Action: req.Action,
			Target: req.Target,
			DryRun: r.DryRun,
			Detail: "refused: " + err.Error(),
		}
		_ = r.Audit.Intent(now, req, r.DryRun)
		_ = r.Audit.Result(now, req, res)
		return res
	}

	// 2. Audit the intent BEFORE doing anything.
	_ = r.Audit.Intent(now, req, r.DryRun)

	// 3. Dry-run: return the planned action and audit it. Execute is NOT called.
	if r.DryRun {
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

	// 4. Live path: execute and audit the real outcome.
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
	case ActionRevokeKey:
		return "remove the authorized_keys line matching fingerprint from " + req.Target
	case ActionBlockHash:
		return "add a fapolicyd deny rule for sha256 " + req.Target
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
	case ActionQuarantine:
		return "chattr -i <quarantined> && mv <quarantined> " + req.Target
	case ActionRevokeKey:
		return "restore " + req.Target + " from its .dsuite.bak backup"
	case ActionBlockHash:
		return "remove the fapolicyd deny rule and reload"
	default:
		return ""
	}
}
