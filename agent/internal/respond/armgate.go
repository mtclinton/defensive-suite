package respond

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
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
	// SoakAttested is the LEGACY existence-only gate: true when the
	// AGENT_AUTORESPONSE_SOAK_ATTESTED artifact merely EXISTS. It is honoured for
	// backward compatibility ONLY when SoakPassAttestationPath is empty. When a path
	// is set, the machine-checked validation (§3) supersedes this flag.
	SoakAttested bool
	// SoakPassAttestationPath points at the AGENT_AUTORESPONSE_SOAK_ATTESTED file
	// (env via config). When non-empty the gate PARSES + VALIDATES it per §3 (schema,
	// duration, zero-FP, freshness, host-class) instead of trusting mere existence.
	// Any validation failure ⇒ the soak precondition is UNMET (fail-closed).
	SoakPassAttestationPath string
	// HostClass is the arming host's class (e.g. "workstation"/"server"). The
	// attestation's host_class must match it (a workstation soak does not attest a
	// server arm, §3). Empty ⇒ the attestation must also carry an empty host_class.
	HostClass string
	// AttestationMaxAge bounds attestation staleness (§3, default 30d when zero). An
	// attestation whose generated_at is older than this is REFUSED.
	AttestationMaxAge time.Duration
	// now is an injectable clock for the freshness check (tests pass a fixed time;
	// nil ⇒ time.Now).
	now func() time.Time
	// readFile is an injectable attestation reader (tests inject in-memory content;
	// nil ⇒ os.ReadFile). Fail-closed: a read error ⇒ the soak precondition is unmet.
	readFile func(string) ([]byte, error)

	// AuthenticatedExport is true when AGENT_TETRAGON_SOURCE selects an
	// authenticated export (grpc/socket), NOT the default file tail (§5 row 3 caps
	// file-tail at shadow).
	AuthenticatedExport bool
}

// deferredUnmet are the safety rails STILL NOT built after this increment. Three
// of the original five rails ARE built here (the bridge→Respond wire via the
// AutoActuator + Bridge.ActionIntents accessor, the grace/veto CANCEL queue, and
// the §4.3 lockout watchdog + auto-rollback) and have been REMOVED from this list.
// The remaining TWO are genuinely unbuilt — and because they are unconditionally
// unmet (no config satisfies them in this build), ArmingPreconditions(canary|armed)
// STILL returns them, so canary/armed are STILL fatally refused at startup. THIS is
// the runtime-inert guarantee: the new machinery has no runtime caller and nothing
// fires on a running agentd. (TestArmingStillRefusedInThisBuild pins this.)
var deferredUnmet = []string{
	"the agentd→console push channel for notify-and-undo (§4.6) — without it the grace/veto has no operator to notify",
	"the authenticated gRPC/socket Tetragon export implementation (the file tail can only reach shadow, §5 #3)",
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
	if reason := soakUnmetReason(in); reason != "" {
		missing = append(missing, reason)
	}
	if !in.AuthenticatedExport {
		missing = append(missing, "an authenticated Tetragon export (set AGENT_TETRAGON_SOURCE=grpc; the default file tail can only reach shadow, per §5 #3)")
	}
	// The deferred safety mechanisms are unconditionally unmet in this build.
	missing = append(missing, deferredUnmet...)
	return missing
}

// ─────────────────────────────────────────────────────────────────────────────
// §3 Soak-pass attestation — the new arm precondition (machine-checked).
// ─────────────────────────────────────────────────────────────────────────────

// soakAttestationSchema is the only accepted attestation schema (§3).
const soakAttestationSchema = "dsuite.soak.attestation/v1"

// soakMinDurationDays is the minimum soak length the attestation must record (§3).
const soakMinDurationDays = 14

// defaultAttestationMaxAge bounds attestation staleness when AttestationMaxAge is
// unset (§3 default 30d).
const defaultAttestationMaxAge = 30 * 24 * time.Hour

// soakClockSkew is the small allowance for a generated_at slightly in the future
// (clock drift between the operator's host and the arming host). Beyond this a
// future-dated attestation is REFUSED (M5: a future timestamp must not pass the
// freshness check by making `age` negative).
const soakClockSkew = 5 * time.Minute

// soakAttestation is the machine-checked artifact the operator produces from
// soak-report.sh output after a triaged ≥14-day shadow soak (§3). agentd NEVER
// generates it. This is the VALUE view used by the validator (and the test
// fixtures); the wire is decoded into soakAttestationWire (pointer fields) so a
// MISSING required field is distinguishable from a present zero and REFUSED
// (fail-closed), not silently accepted as 0.
type soakAttestation struct {
	Schema                  string    `json:"schema"`
	DurationDays            float64   `json:"duration_days"`
	DistinctWouldQuarantine int       `json:"distinct_would_quarantine"`
	UnexplainedFP           int       `json:"unexplained_fp"`
	GeneratedAt             time.Time `json:"generated_at"`
	HostClass               string    `json:"host_class"`
}

// soakAttestationWire is the DECODE view: every required §3 field is a POINTER so a
// nil (absent-from-JSON) field is a fail-closed refusal rather than a silent zero
// (M5). A present field is dereferenced into the validated value struct.
type soakAttestationWire struct {
	Schema                  *string  `json:"schema"`
	DurationDays            *float64 `json:"duration_days"`
	DistinctWouldQuarantine *int     `json:"distinct_would_quarantine"`
	UnexplainedFP           *int     `json:"unexplained_fp"`
	GeneratedAt             *string  `json:"generated_at"`
	HostClass               *string  `json:"host_class"`
}

// soakUnmetReason returns "" when the soak precondition is SATISFIED, else a
// precise reason string for the refusal list. It is FAIL-CLOSED: absent/
// unparseable/short/non-zero-FP/stale/future-dated/host-class-mismatch AND any
// MISSING required field / trailing-or-decoy JSON all return a non-empty reason.
// The legacy existence-only SoakAttested bool is honoured ONLY when no
// SoakPassAttestationPath is configured (backward compatibility).
func soakUnmetReason(in ArmingInputs) string {
	const hint = " (set AGENT_AUTORESPONSE_SOAK_ATTESTED to a valid post-soak attestation)"

	if strings.TrimSpace(in.SoakPassAttestationPath) == "" {
		// No path configured → fall back to the legacy existence gate.
		if in.SoakAttested {
			return ""
		}
		return "a passed FP-soak attestation artifact" + hint + "; absent by default"
	}

	read := in.readFile
	if read == nil {
		read = os.ReadFile
	}
	raw, err := read(in.SoakPassAttestationPath)
	if err != nil {
		return "the FP-soak attestation could not be read" + hint + " (fail-closed: " + err.Error() + ")"
	}

	// Decode the single top-level object. Unknown fields are tolerated (operator
	// reports may carry extra context), but a trailing token / a SECOND object after
	// the first is REFUSED: json.Decoder.Decode reads only the first value and would
	// otherwise silently ignore a decoy object that smuggles a second, different
	// attestation past the gate (M5).
	var wire soakAttestationWire
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&wire); err != nil {
		return "the FP-soak attestation is unparseable" + hint + " (fail-closed: " + err.Error() + ")"
	}
	if dec.More() {
		return "the FP-soak attestation has trailing data after the JSON object (a decoy/second object) — refusing (fail-closed)"
	}

	// Every required §3 field MUST be present (nil pointer ⇒ absent-from-JSON ⇒
	// refuse). A present-but-zero field is distinct from absent and validated below.
	if wire.Schema == nil {
		return "the FP-soak attestation is missing the required \"schema\" field (fail-closed)"
	}
	if wire.DurationDays == nil {
		return "the FP-soak attestation is missing the required \"duration_days\" field (fail-closed)"
	}
	if wire.DistinctWouldQuarantine == nil {
		return "the FP-soak attestation is missing the required \"distinct_would_quarantine\" field (fail-closed)"
	}
	if wire.UnexplainedFP == nil {
		return "the FP-soak attestation is missing the required \"unexplained_fp\" field (fail-closed)"
	}
	if wire.GeneratedAt == nil {
		return "the FP-soak attestation is missing the required \"generated_at\" field (fail-closed)"
	}
	if wire.HostClass == nil {
		return "the FP-soak attestation is missing the required \"host_class\" field (fail-closed)"
	}

	genAt, perr := time.Parse(time.RFC3339, strings.TrimSpace(*wire.GeneratedAt))
	if perr != nil {
		return "the FP-soak attestation generated_at is not an RFC3339 timestamp — cannot verify freshness (fail-closed)"
	}
	att := soakAttestation{
		Schema:                  *wire.Schema,
		DurationDays:            *wire.DurationDays,
		DistinctWouldQuarantine: *wire.DistinctWouldQuarantine,
		UnexplainedFP:           *wire.UnexplainedFP,
		GeneratedAt:             genAt,
		HostClass:               *wire.HostClass,
	}

	if att.Schema != soakAttestationSchema {
		return fmt.Sprintf("the FP-soak attestation schema %q is not the required %q (fail-closed)", att.Schema, soakAttestationSchema)
	}
	if att.DurationDays < soakMinDurationDays {
		return fmt.Sprintf("the FP-soak ran only %g days (need >= %d) — soak too short (fail-closed)", att.DurationDays, soakMinDurationDays)
	}
	if att.DistinctWouldQuarantine > 0 {
		return fmt.Sprintf("the FP-soak recorded %d distinct would-quarantine candidate(s) (need <= 0) — un-triaged false positives (fail-closed)", att.DistinctWouldQuarantine)
	}
	if att.UnexplainedFP != 0 {
		return fmt.Sprintf("the FP-soak recorded %d unexplained false positive(s) (need 0) (fail-closed)", att.UnexplainedFP)
	}
	maxAge := in.AttestationMaxAge
	if maxAge <= 0 {
		maxAge = defaultAttestationMaxAge
	}
	now := time.Now
	if in.now != nil {
		now = in.now
	}
	if att.GeneratedAt.IsZero() {
		return "the FP-soak attestation has no generated_at timestamp — cannot verify freshness (fail-closed)"
	}
	age := now().Sub(att.GeneratedAt)
	// M5: a FUTURE-dated attestation (age negative beyond a small clock skew) is
	// REFUSED — otherwise a future generated_at trivially passes the `age > maxAge`
	// staleness check and forges freshness.
	if age < -soakClockSkew {
		return fmt.Sprintf("the FP-soak attestation generated_at is in the FUTURE (by %s, beyond the %s skew) — refusing (fail-closed)", (-age).Round(time.Second), soakClockSkew)
	}
	if age > maxAge {
		return fmt.Sprintf("the FP-soak attestation is stale (generated %s ago, max %s) (fail-closed)", age.Round(time.Hour), maxAge)
	}
	if att.HostClass != in.HostClass {
		return fmt.Sprintf("the FP-soak attestation host_class %q does not match the arming host class %q (a soak on one class does not attest another) (fail-closed)", att.HostClass, in.HostClass)
	}
	return "" // every §3 field validated → the soak precondition is SATISFIED
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
