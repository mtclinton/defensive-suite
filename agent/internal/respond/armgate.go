package respond

import (
	"fmt"
	"strings"
)

// armgate.go implements the §E / §7 ARMING-PRECONDITION gate for canary/armed.
//
// ═══ SAFETY INVARIANT (this increment) ═══
// canary/armed are STILL a fatal preflight error. They are no longer refused with
// a flat "not implemented"; they are gated on concrete, currently-UNSATISFIABLE
// preconditions and refused with a PRECISE, HONEST list of exactly what is
// missing. Because the deferred safety mechanisms (the bridge→Respond wire, the
// grace/veto queue, the agentd→console push channel, the reachability/lockout
// watchdog + auto-rollback, the authenticated gRPC export) are NOT built in this
// increment, ArmingPreconditions ALWAYS returns at least those unmet items — so
// auto-response cannot fire after this increment.

// ArmingInputs are the operator-supplied, config-derived facts the arming gate
// checks. They are the ONLY satisfiable preconditions in this build; the deferred
// safety mechanisms are unconditionally unmet (see deferredUnmet).
type ArmingInputs struct {
	// SoakAttested is true when the AGENT_AUTORESPONSE_SOAK_ATTESTED artifact is
	// present (the operator's post-soak attestation, §7.2).
	SoakAttested bool
	// AuthenticatedExport is true when AGENT_TETRAGON_SOURCE selects an
	// authenticated export (grpc/socket), NOT the default file tail (§5 row 3 caps
	// file-tail at shadow).
	AuthenticatedExport bool
}

// deferredUnmet are the §"DEFER" safety mechanisms NOT built in this increment.
// They are listed verbatim in every canary/armed refusal so the message is honest
// about what stands between this build and a live canary. They are
// unconditionally unmet here (there is no config that satisfies them in this
// build) — which is exactly why canary/armed are still refused.
var deferredUnmet = []string{
	"the bridge→Respond connection (the un-gating; the bridge still cannot execute)",
	"the grace/veto (CANCEL) queue (§4.6)",
	"the agentd→console push channel for notify-and-undo (§4.6)",
	"the §4.3 reachability/lockout watchdog + auto-rollback",
	"the authenticated gRPC/socket Tetragon export implementation (only its preflight gate exists)",
}

// ArmingPreconditions returns the list of UNMET preconditions for running mode
// live. For off/dry-run/shadow it returns nil (those modes never execute and are
// always permitted). For canary/armed it returns every unmet item: the
// operator-satisfiable gates that are absent (soak attestation, authenticated
// export) PLUS the deferred safety mechanisms (always unmet in this build). A
// non-empty result means the mode is REFUSED. The list is precise and ordered so
// the printed error enumerates exactly what is missing.
func ArmingPreconditions(mode Mode, in ArmingInputs) []string {
	if mode != ModeCanary && mode != ModeArmed {
		return nil // off/dry-run/shadow never execute → no arming preconditions
	}
	var missing []string
	if !in.SoakAttested {
		missing = append(missing, "a passed FP-soak attestation artifact (set AGENT_AUTORESPONSE_SOAK_ATTESTED to the post-soak report path; absent by default)")
	}
	if !in.AuthenticatedExport {
		missing = append(missing, "an authenticated Tetragon export (set AGENT_TETRAGON_SOURCE=grpc; the default file tail can only reach shadow, per §5 #3)")
	}
	// The deferred safety mechanisms are unconditionally unmet in this build.
	missing = append(missing, deferredUnmet...)
	return missing
}

// AuthenticatedTetragonSource reports whether a Tetragon source string selects an
// authenticated export (grpc/socket) rather than the default file tail. The
// authenticated export is NOT implemented in this build (only this gate is), so a
// "grpc" value still cannot ARM on its own — the deferred mechanisms keep
// canary/armed refused — but it lets the gate report the source precondition as
// satisfiable and pinpoint the remaining blockers.
func AuthenticatedTetragonSource(src string) bool {
	switch strings.ToLower(strings.TrimSpace(src)) {
	case "grpc", "socket", "grpc-tls", "unix":
		return true
	default: // "", "file", "tail", anything else → unauthenticated file tail
		return false
	}
}

// ArmingRefusalError builds the FATAL, honest refusal error for a canary/armed
// mode whose preconditions are unmet, enumerating each missing item. The caller
// (cmdRun/cmdPreflight) prints it and exits non-zero. missing must be non-empty.
func ArmingRefusalError(mode Mode, missing []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "auto-response mode %q is REFUSED: %d arming precondition(s) are not met in this build:", mode, len(missing))
	for _, m := range missing {
		b.WriteString("\n  - ")
		b.WriteString(m)
	}
	b.WriteString("\nauto-response cannot fire; stay at off|dry-run|shadow until these are built and the FP soak passes.")
	return fmt.Errorf("%s", b.String())
}
