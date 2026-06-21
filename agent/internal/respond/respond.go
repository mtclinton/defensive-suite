// Package respond is agentd's manual-response core (Phase 1, M3). It turns an
// operator-issued Request ("kill this PID", "isolate this host", …) into a
// guarded, audited, reversible-where-possible action.
//
// The whole package is built around one safety rule: NOTHING destructive runs
// unless an operator has explicitly enabled it. Two independent gates enforce
// that:
//
//  1. DryRun (a Responder field, default TRUE): in dry-run, Respond validates
//     and audits the request and returns "what it WOULD do", but never calls the
//     Executor. The agent's config ResponseEnabled (default FALSE) is what flips
//     DryRun off.
//  2. The Executor INTERFACE: the side-effecting RealExecutor (syscall.Kill,
//     nft, chattr, …) is one implementation; FakeExecutor (records, does nothing)
//     is the other. All tests use FakeExecutor; RealExecutor is never invoked in
//     tests.
//
// Every request is Validate()d (pure guardrails) and written to an append-only
// AuditLog before any execution can happen.
package respond

import "fmt"

// Action names the kind of response. These are the five M3 actuators plus the
// Phase 4 §4.6 reverse actuators (Unquarantine/DeIsolate/RestoreKey) and the
// §3.2/§4.2 identity-bound, fd-based quarantine.
const (
	ActionKill       = "kill"       // SIGKILL a PID (+children, in the real executor)
	ActionIsolate    = "isolate"    // nftables drop-egress except mgmt ifaces
	ActionQuarantine = "quarantine" // move a file aside + chattr +i / chmod 000
	ActionRevokeKey  = "revoke-key" // remove an authorized_keys line by fingerprint
	ActionBlockHash  = "block-hash" // fapolicyd deny rule by sha256

	// --- Phase 4 §4.6 first-class REVERSE actuators ---
	// These exist so UNDO is a structured Request flowing through Validate →
	// kill-switch → rate-limit → audit, NOT a shelled free-text string. Like every
	// actuator they are MANUAL-invocable, GUARDED, and DRY-RUN by default; they
	// never auto-fire in this build.

	// ActionUnquarantine reverses a quarantine: chattr -i the quarantined copy and
	// mv it back to its recorded origin. Target is the quarantine-dst (must be
	// under the quarantine dir); the "origin" arg is the path to restore to.
	ActionUnquarantine = "unquarantine"
	// ActionDeIsolate reverses an isolate: nft delete the dsuite_isolate table.
	ActionDeIsolate = "de-isolate"
	// ActionRestoreKey reverses a revoke-key: restore authorized_keys from its
	// .dsuite.bak backup. Target is the authorized_keys path (validated like
	// revoke-key).
	ActionRestoreKey = "restore-key"

	// --- Phase 4 §3.2/§4.2 identity-bound, fd-based quarantine ---
	// ActionQuarantineFD is a hardened quarantine that binds to LIVE process
	// identity: the Request carries the captured exec_id + pid + starttime + uid +
	// StagingDir constraint, and at execute time the executor RE-RESOLVES /proc,
	// REQUIRES a still-live process whose (exec_id, starttime) match AND whose
	// realpath is resident under a configured StagingDir, opens O_NOFOLLOW + fstat,
	// and acts BY FD (so checked==acted). It REFUSES any target outside StagingDirs
	// or on identity mismatch. Guarded + dry-run-default like every actuator.
	ActionQuarantineFD = "quarantine-fd"
)

// Request is an operator-issued response action. Args carries action-specific
// parameters (e.g. revoke-key's "fingerprint"); Reason and Actor are recorded in
// the audit log so every action is attributable.
//
// DryRun is a Phase 4 §4.4 PER-ACTION arming override: when non-nil it overrides
// the Responder-level DryRun for THIS request only, so a single responder can run
// ONE action live while every other stays dry. When nil (the default, and the
// only form the manual socket ever sets), the Responder-level DryRun is used and
// manual behaviour is byte-for-byte identical to before. A per-action-live request
// still flows through Validate → kill-switch → rate-limit → audit unchanged: there
// is no path that skips a brake and no second executor.
type Request struct {
	Action string            `json:"action"`
	Target string            `json:"target"`
	Args   map[string]string `json:"args,omitempty"`
	Reason string            `json:"reason,omitempty"`
	Actor  string            `json:"actor,omitempty"`
	// DryRun, when non-nil, overrides the Responder's DryRun for this request only
	// (§4.4 per-action arming). It is NOT marshalled from the operator socket (the
	// HTTP handler never sets it), so manual response can never arm itself live via
	// the wire — only the in-process auto path (a LATER increment) sets it.
	DryRun *bool `json:"-"`
}

// Result is the outcome of a Respond call. In dry-run, DryRun is true and Detail
// describes what WOULD happen; Undo, when non-empty, is the human-readable
// command/note for reversing the action.
type Result struct {
	OK     bool   `json:"ok"`
	Action string `json:"action"`
	Target string `json:"target"`
	DryRun bool   `json:"dry_run"`
	Detail string `json:"detail,omitempty"`
	Undo   string `json:"undo,omitempty"`
}

// arg returns the trimmed Args value for k, or "".
func (r Request) arg(k string) string {
	if r.Args == nil {
		return ""
	}
	return r.Args[k]
}

// dryRun resolves the effective dry-run mode for this request (§4.4): the
// per-Request override when set, else the Responder-level default. Kept here so
// the precedence is in one place.
func (r Request) dryRun(responderDefault bool) bool {
	if r.DryRun != nil {
		return *r.DryRun
	}
	return responderDefault
}

// String renders a Request compactly for audit detail / errors.
func (r Request) String() string {
	return fmt.Sprintf("%s %s", r.Action, r.Target)
}
