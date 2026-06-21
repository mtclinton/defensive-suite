package respond

import (
	"strings"
	"testing"
)

// --- §E/§7 arming gate: canary/armed REFUSED with a precise list; safe modes OK ---

func TestArmingPreconditionsSafeModesAlwaysPermitted(t *testing.T) {
	for _, m := range []Mode{ModeOff, ModeDryRun, ModeShadow} {
		// Even with NO satisfiable preconditions, the safe (never-executing) modes
		// have no arming requirements.
		if missing := ArmingPreconditions(m, ArmingInputs{}); len(missing) != 0 {
			t.Errorf("mode %v must have no arming preconditions, got %v", m, missing)
		}
	}
}

// canary/armed are ALWAYS refused in this build (the deferred mechanisms are
// unconditionally unmet), even when the operator HAS satisfied every config gate.
func TestArmingPreconditionsCanaryArmedAlwaysRefused(t *testing.T) {
	for _, m := range []Mode{ModeCanary, ModeArmed} {
		// Best case: both config gates satisfied.
		missing := ArmingPreconditions(m, ArmingInputs{SoakAttested: true, AuthenticatedExport: true})
		if len(missing) == 0 {
			t.Fatalf("mode %v must STILL be refused in this build (deferred mechanisms unmet)", m)
		}
		// The deferred items must all be present in the list.
		joined := strings.Join(missing, "\n")
		for _, want := range deferredUnmet {
			if !strings.Contains(joined, want) {
				t.Errorf("mode %v missing list should enumerate %q; got:\n%s", m, want, joined)
			}
		}
		// The bridge→Respond wire is the load-bearing un-gating; it must be named.
		if !strings.Contains(joined, "bridge→Respond") {
			t.Errorf("mode %v refusal must name the bridge→Respond un-gating as missing:\n%s", m, joined)
		}
	}
}

// When the config gates are UNMET, they appear in the list too (precise + honest).
func TestArmingPreconditionsEnumeratesConfigGaps(t *testing.T) {
	missing := ArmingPreconditions(ModeCanary, ArmingInputs{SoakAttested: false, AuthenticatedExport: false})
	joined := strings.Join(missing, "\n")
	if !strings.Contains(joined, "AGENT_AUTORESPONSE_SOAK_ATTESTED") {
		t.Errorf("an unmet soak attestation must be enumerated:\n%s", joined)
	}
	if !strings.Contains(joined, "AGENT_TETRAGON_SOURCE") {
		t.Errorf("an unmet authenticated export must be enumerated:\n%s", joined)
	}

	// When satisfied, those two are NOT in the list (only the deferred items are).
	met := ArmingPreconditions(ModeCanary, ArmingInputs{SoakAttested: true, AuthenticatedExport: true})
	mj := strings.Join(met, "\n")
	if strings.Contains(mj, "AGENT_AUTORESPONSE_SOAK_ATTESTED") {
		t.Errorf("a SATISFIED soak attestation must not be listed:\n%s", mj)
	}
	if strings.Contains(mj, "AGENT_TETRAGON_SOURCE") {
		t.Errorf("a SATISFIED authenticated export must not be listed:\n%s", mj)
	}
}

func TestAuthenticatedTetragonSource(t *testing.T) {
	cases := map[string]bool{
		"":       false,
		"file":   false,
		"tail":   false,
		"grpc":   true,
		"GRPC":   true,
		"socket": true,
		"unix":   true,
		"junk":   false,
	}
	for in, want := range cases {
		if got := AuthenticatedTetragonSource(in); got != want {
			t.Errorf("AuthenticatedTetragonSource(%q)=%v want %v", in, got, want)
		}
	}
}

func TestArmingRefusalErrorEnumerates(t *testing.T) {
	missing := ArmingPreconditions(ModeCanary, ArmingInputs{})
	err := ArmingRefusalError(ModeCanary, missing)
	if err == nil {
		t.Fatal("expected a refusal error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "REFUSED") || !strings.Contains(msg, "canary") {
		t.Errorf("refusal message should name the mode + REFUSED: %q", msg)
	}
	for _, m := range missing {
		if !strings.Contains(msg, m) {
			t.Errorf("refusal message should enumerate %q:\n%s", m, msg)
		}
	}
}

// ParseRequestedMode is un-clamped: canary/armed map to their real modes (the
// input to the arming gate), while ParseMode stays clamped (never canary/armed).
func TestParseRequestedModeUnclamped(t *testing.T) {
	cases := map[string]Mode{
		"":                 ModeOff,
		"off":              ModeOff,
		"dry-run":          ModeDryRun,
		"shadow":           ModeShadow,
		"canary":           ModeCanary,
		"armed":            ModeArmed,
		"armed:quarantine": ModeArmed,
		"garbage":          ModeOff,
	}
	for in, want := range cases {
		if got := ParseRequestedMode(in); got != want {
			t.Errorf("ParseRequestedMode(%q)=%v want %v", in, got, want)
		}
		// ParseMode must NEVER return canary/armed (the safe clamp).
		if cm, _ := ParseMode(in); cm == ModeCanary || cm == ModeArmed {
			t.Errorf("ParseMode(%q) returned an executing mode %v — clamp broken", in, cm)
		}
	}
}
