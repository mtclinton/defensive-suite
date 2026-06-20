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

// Action names the kind of response. These are the five M3 actuators.
const (
	ActionKill       = "kill"       // SIGKILL a PID (+children, in the real executor)
	ActionIsolate    = "isolate"    // nftables drop-egress except mgmt ifaces
	ActionQuarantine = "quarantine" // move a file aside + chattr +i / chmod 000
	ActionRevokeKey  = "revoke-key" // remove an authorized_keys line by fingerprint
	ActionBlockHash  = "block-hash" // fapolicyd deny rule by sha256
)

// Request is an operator-issued response action. Args carries action-specific
// parameters (e.g. revoke-key's "fingerprint"); Reason and Actor are recorded in
// the audit log so every action is attributable.
type Request struct {
	Action string            `json:"action"`
	Target string            `json:"target"`
	Args   map[string]string `json:"args,omitempty"`
	Reason string            `json:"reason,omitempty"`
	Actor  string            `json:"actor,omitempty"`
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

// String renders a Request compactly for audit detail / errors.
func (r Request) String() string {
	return fmt.Sprintf("%s %s", r.Action, r.Target)
}
