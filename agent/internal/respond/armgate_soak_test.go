package respond

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// armgate_soak_test.go covers §3 (soak-pass attestation validation) and the
// runtime-inert guarantee (§2.2): canary/armed remain fatally refused in this build
// EVEN with a perfect soak attestation + authenticated export, because the two
// genuinely-unbuilt rails stay in deferredUnmet.

// attestNow is the fixed "now" the soak freshness check is evaluated against.
var attestNow = time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

// validAttestation is a soak attestation that passes EVERY §3 field. Individual
// tests mutate one field to prove that field alone flips the gate to unmet.
func validAttestation() soakAttestation {
	return soakAttestation{
		Schema:                  soakAttestationSchema,
		DurationDays:            21,
		DistinctWouldQuarantine: 0,
		UnexplainedFP:           0,
		GeneratedAt:             attestNow.Add(-3 * 24 * time.Hour), // 3 days old
		HostClass:               "workstation",
	}
}

// armingInputsFor wraps an attestation as in-memory file content + a fixed clock,
// with the authenticated export satisfied, host-class "workstation". The soak
// path is set so the §3 validation runs (not the legacy existence gate).
func armingInputsFor(att soakAttestation) ArmingInputs {
	body, _ := json.Marshal(att)
	return ArmingInputs{
		SoakPassAttestationPath: "/etc/agentd/soak.json",
		HostClass:               "workstation",
		AuthenticatedExport:     true,
		now:                     func() time.Time { return attestNow },
		readFile:                func(string) ([]byte, error) { return body, nil },
	}
}

// soakSatisfied reports whether the soak precondition specifically is MET for
// these inputs (its reason string is empty).
func soakSatisfied(in ArmingInputs) bool {
	return soakUnmetReason(in) == ""
}

// TestArmingStillRefusedInThisBuild is the runtime-inert guarantee (§2.2): even
// with a PERFECT soak attestation AND an authenticated export, canary/armed are
// STILL refused because the two genuinely-unbuilt rails (console push +
// authenticated export impl) remain in deferredUnmet. Nothing fires on a running
// agentd in this build.
func TestArmingStillRefusedInThisBuild(t *testing.T) {
	in := armingInputsFor(validAttestation())

	// Sanity: the soak gate itself is satisfied by this perfect attestation.
	if !soakSatisfied(in) {
		t.Fatalf("the perfect attestation should satisfy the soak gate; reason=%q", soakUnmetReason(in))
	}

	for _, m := range []Mode{ModeCanary, ModeArmed} {
		missing := ArmingPreconditions(m, in)
		if len(missing) == 0 {
			t.Fatalf("mode %v MUST still be refused in this build (unbuilt rails remain)", m)
		}
		joined := strings.Join(missing, "\n")
		// The refusal must be SOLELY the two unbuilt rails (soak + export satisfied).
		if strings.Contains(joined, "FP-soak") {
			t.Errorf("a SATISFIED soak must not appear in the refusal list:\n%s", joined)
		}
		if strings.Contains(joined, "AGENT_TETRAGON_SOURCE") {
			t.Errorf("a SATISFIED authenticated export must not appear:\n%s", joined)
		}
		for _, want := range deferredUnmet {
			if !strings.Contains(joined, want) {
				t.Errorf("mode %v refusal must enumerate the unbuilt rail %q:\n%s", m, want, joined)
			}
		}
		// Exactly the two unbuilt rails — no more, no fewer.
		if len(missing) != len(deferredUnmet) {
			t.Errorf("mode %v: expected exactly the %d unbuilt rails, got %d: %v", m, len(deferredUnmet), len(missing), missing)
		}
	}

	// And there are exactly TWO unbuilt rails (the bridge wire / grace / watchdog
	// were built and removed this increment).
	if len(deferredUnmet) != 2 {
		t.Fatalf("deferredUnmet should retain exactly the 2 unbuilt rails, got %d: %v", len(deferredUnmet), deferredUnmet)
	}
}

// --- §3 soak attestation: each failing field refuses; the valid shape passes. ---

func TestSoakAttestationValidShapePasses(t *testing.T) {
	if reason := soakUnmetReason(armingInputsFor(validAttestation())); reason != "" {
		t.Fatalf("a valid attestation must satisfy the soak gate, got reason: %q", reason)
	}
}

func TestSoakAttestationBadSchemaRefuses(t *testing.T) {
	att := validAttestation()
	att.Schema = "dsuite.soak.attestation/v2"
	if reason := soakUnmetReason(armingInputsFor(att)); reason == "" {
		t.Fatal("a wrong schema must refuse the soak gate")
	} else if !strings.Contains(reason, "schema") {
		t.Errorf("reason should name the schema mismatch: %q", reason)
	}
}

func TestSoakAttestationShortDurationRefuses(t *testing.T) {
	att := validAttestation()
	att.DurationDays = 13 // < 14
	if reason := soakUnmetReason(armingInputsFor(att)); reason == "" {
		t.Fatal("a <14-day soak must refuse")
	} else if !strings.Contains(reason, "too short") {
		t.Errorf("reason should name the short duration: %q", reason)
	}
}

func TestSoakAttestationNonZeroWouldQuarantineRefuses(t *testing.T) {
	att := validAttestation()
	att.DistinctWouldQuarantine = 1 // one un-triaged FP
	if reason := soakUnmetReason(armingInputsFor(att)); reason == "" {
		t.Fatal("a non-zero distinct_would_quarantine must refuse")
	} else if !strings.Contains(reason, "would-quarantine") {
		t.Errorf("reason should name the would-quarantine count: %q", reason)
	}
}

func TestSoakAttestationNonZeroUnexplainedFPRefuses(t *testing.T) {
	att := validAttestation()
	att.UnexplainedFP = 2
	if reason := soakUnmetReason(armingInputsFor(att)); reason == "" {
		t.Fatal("a non-zero unexplained_fp must refuse")
	} else if !strings.Contains(reason, "unexplained false positive") {
		t.Errorf("reason should name the unexplained FPs: %q", reason)
	}
}

func TestSoakAttestationStaleRefuses(t *testing.T) {
	att := validAttestation()
	att.GeneratedAt = attestNow.Add(-40 * 24 * time.Hour) // 40 days > 30-day default
	if reason := soakUnmetReason(armingInputsFor(att)); reason == "" {
		t.Fatal("a stale (>30d) attestation must refuse")
	} else if !strings.Contains(reason, "stale") {
		t.Errorf("reason should name staleness: %q", reason)
	}
}

func TestSoakAttestationMissingGeneratedAtRefuses(t *testing.T) {
	att := validAttestation()
	att.GeneratedAt = time.Time{} // zero
	if reason := soakUnmetReason(armingInputsFor(att)); reason == "" {
		t.Fatal("an attestation with no generated_at must refuse")
	} else if !strings.Contains(reason, "generated_at") {
		t.Errorf("reason should name the missing timestamp: %q", reason)
	}
}

func TestSoakAttestationHostClassMismatchRefuses(t *testing.T) {
	att := validAttestation()
	att.HostClass = "server" // arming host is "workstation"
	if reason := soakUnmetReason(armingInputsFor(att)); reason == "" {
		t.Fatal("a host_class mismatch must refuse")
	} else if !strings.Contains(reason, "host_class") {
		t.Errorf("reason should name the host_class mismatch: %q", reason)
	}
}

func TestSoakAttestationUnparseableRefuses(t *testing.T) {
	in := ArmingInputs{
		SoakPassAttestationPath: "/etc/agentd/soak.json",
		HostClass:               "workstation",
		AuthenticatedExport:     true,
		now:                     func() time.Time { return attestNow },
		readFile:                func(string) ([]byte, error) { return []byte("{not json"), nil },
	}
	if reason := soakUnmetReason(in); reason == "" {
		t.Fatal("an unparseable attestation must refuse")
	} else if !strings.Contains(reason, "unparseable") {
		t.Errorf("reason should say unparseable: %q", reason)
	}
}

func TestSoakAttestationUnreadableRefuses(t *testing.T) {
	in := ArmingInputs{
		SoakPassAttestationPath: "/etc/agentd/soak.json",
		HostClass:               "workstation",
		AuthenticatedExport:     true,
		now:                     func() time.Time { return attestNow },
		readFile:                func(string) ([]byte, error) { return nil, errReadFail },
	}
	if reason := soakUnmetReason(in); reason == "" {
		t.Fatal("an unreadable attestation must refuse (fail-closed)")
	} else if !strings.Contains(reason, "could not be read") {
		t.Errorf("reason should say it could not be read: %q", reason)
	}
}

// armingInputsRaw wraps RAW JSON bytes (not a marshaled struct) as the
// attestation content, so a test can omit a field, append a decoy object, or
// future-date the timestamp — shapes the value-struct fixtures cannot express.
func armingInputsRaw(raw string) ArmingInputs {
	return ArmingInputs{
		SoakPassAttestationPath: "/etc/agentd/soak.json",
		HostClass:               "workstation",
		AuthenticatedExport:     true,
		now:                     func() time.Time { return attestNow },
		readFile:                func(string) ([]byte, error) { return []byte(raw), nil },
	}
}

// validRawAttestation is the canonical valid attestation as RAW JSON (3 days old),
// so individual M5 tests can delete one key / append a decoy and prove the
// fail-closed refusal.
func validRawAttestation() string {
	gen := attestNow.Add(-3 * 24 * time.Hour).Format(time.RFC3339)
	return `{"schema":"` + soakAttestationSchema + `","duration_days":21,` +
		`"distinct_would_quarantine":0,"unexplained_fp":0,` +
		`"generated_at":"` + gen + `","host_class":"workstation"}`
}

// M5: the canonical RAW shape passes (sanity for the raw-JSON tests below).
func TestSoakRawValidShapePasses(t *testing.T) {
	if reason := soakUnmetReason(armingInputsRaw(validRawAttestation())); reason != "" {
		t.Fatalf("the canonical raw attestation must pass, got: %q", reason)
	}
}

// M5: a MISSING required field decodes to a nil pointer ⇒ REFUSE (it must NOT
// silently decode to 0/"" and pass). Each required key is removed in turn.
func TestSoakMissingRequiredFieldRefuses(t *testing.T) {
	gen := attestNow.Add(-3 * 24 * time.Hour).Format(time.RFC3339)
	// Each case omits exactly one required field.
	cases := map[string]string{
		"schema":                    `{"duration_days":21,"distinct_would_quarantine":0,"unexplained_fp":0,"generated_at":"` + gen + `","host_class":"workstation"}`,
		"duration_days":             `{"schema":"` + soakAttestationSchema + `","distinct_would_quarantine":0,"unexplained_fp":0,"generated_at":"` + gen + `","host_class":"workstation"}`,
		"distinct_would_quarantine": `{"schema":"` + soakAttestationSchema + `","duration_days":21,"unexplained_fp":0,"generated_at":"` + gen + `","host_class":"workstation"}`,
		"unexplained_fp":            `{"schema":"` + soakAttestationSchema + `","duration_days":21,"distinct_would_quarantine":0,"generated_at":"` + gen + `","host_class":"workstation"}`,
		"generated_at":              `{"schema":"` + soakAttestationSchema + `","duration_days":21,"distinct_would_quarantine":0,"unexplained_fp":0,"host_class":"workstation"}`,
		"host_class":                `{"schema":"` + soakAttestationSchema + `","duration_days":21,"distinct_would_quarantine":0,"unexplained_fp":0,"generated_at":"` + gen + `"}`,
	}
	for field, raw := range cases {
		reason := soakUnmetReason(armingInputsRaw(raw))
		if reason == "" {
			t.Errorf("a missing %q must REFUSE (must not decode to a silent zero)", field)
		} else if !strings.Contains(reason, field) {
			t.Errorf("the refusal for a missing %q should name the field: %q", field, reason)
		}
	}
}

// M5: trailing garbage after the JSON object is REFUSED (json.Decoder would
// otherwise silently ignore it).
func TestSoakTrailingGarbageRefuses(t *testing.T) {
	raw := validRawAttestation() + "\ngarbage-after-the-object"
	reason := soakUnmetReason(armingInputsRaw(raw))
	if reason == "" {
		t.Fatal("trailing data after the attestation must REFUSE")
	}
	if !strings.Contains(reason, "trailing data") {
		t.Errorf("the refusal should name the trailing data: %q", reason)
	}
}

// M5: a SECOND JSON object after a valid one (a decoy) is REFUSED — the decoder
// must not accept the first and ignore the rest.
func TestSoakTwoObjectsRefuses(t *testing.T) {
	// First object is VALID; the decoy second object is also "valid" but the gate
	// must refuse on the presence of a second object, not silently take the first.
	raw := validRawAttestation() + "\n" + validRawAttestation()
	reason := soakUnmetReason(armingInputsRaw(raw))
	if reason == "" {
		t.Fatal("two stacked JSON objects must REFUSE (decoy second object)")
	}
	if !strings.Contains(reason, "trailing data") && !strings.Contains(reason, "second object") {
		t.Errorf("the refusal should name the decoy/second object: %q", reason)
	}
}

// M5: a FUTURE-dated generated_at (beyond the small clock skew) is REFUSED — it
// must not pass the freshness check by making `age` negative.
func TestSoakFutureTimestampRefuses(t *testing.T) {
	future := attestNow.Add(48 * time.Hour).Format(time.RFC3339)
	raw := `{"schema":"` + soakAttestationSchema + `","duration_days":21,` +
		`"distinct_would_quarantine":0,"unexplained_fp":0,` +
		`"generated_at":"` + future + `","host_class":"workstation"}`
	reason := soakUnmetReason(armingInputsRaw(raw))
	if reason == "" {
		t.Fatal("a future-dated attestation must REFUSE (a future timestamp must not forge freshness)")
	}
	if !strings.Contains(reason, "FUTURE") {
		t.Errorf("the refusal should name the future timestamp: %q", reason)
	}
}

// M5: a generated_at WITHIN the small clock-skew allowance (a few minutes ahead,
// from clock drift) still PASSES — the skew is a deliberate, bounded tolerance.
func TestSoakWithinSkewPasses(t *testing.T) {
	nearFuture := attestNow.Add(2 * time.Minute).Format(time.RFC3339)
	raw := `{"schema":"` + soakAttestationSchema + `","duration_days":21,` +
		`"distinct_would_quarantine":0,"unexplained_fp":0,` +
		`"generated_at":"` + nearFuture + `","host_class":"workstation"}`
	if reason := soakUnmetReason(armingInputsRaw(raw)); reason != "" {
		t.Fatalf("a generated_at within the clock skew must PASS, got: %q", reason)
	}
}

// A valid attestation flips the SOAK field specifically to satisfied, while the
// OVERALL canary/armed list stays non-empty (the unbuilt rails) — proving §3 is
// real but does not by itself un-gate.
func TestSoakAttestationFlipsSoakFieldButOverallStaysRefused(t *testing.T) {
	in := armingInputsFor(validAttestation())

	// The soak field itself is satisfied...
	if !soakSatisfied(in) {
		t.Fatalf("valid attestation should satisfy the soak field; reason=%q", soakUnmetReason(in))
	}
	// ...yet the overall canary list stays non-empty (the two unbuilt rails).
	if missing := ArmingPreconditions(ModeCanary, in); len(missing) == 0 {
		t.Fatal("overall canary preconditions must stay non-empty despite a valid soak")
	}

	// With a BAD soak, the soak reason ALSO appears in the overall list — confirming
	// the soak field is genuinely wired into ArmingPreconditions.
	bad := armingInputsFor(func() soakAttestation { a := validAttestation(); a.DurationDays = 1; return a }())
	missing := ArmingPreconditions(ModeCanary, bad)
	if !strings.Contains(strings.Join(missing, "\n"), "too short") {
		t.Errorf("a bad soak must surface in the overall refusal list: %v", missing)
	}
}

// The legacy existence-only gate still works when no attestation path is set
// (backward compat with the pre-existing arming tests).
func TestSoakLegacyExistenceGateWhenNoPath(t *testing.T) {
	if soakUnmetReason(ArmingInputs{SoakAttested: true}) != "" {
		t.Error("legacy SoakAttested=true with no path should satisfy the soak gate")
	}
	if soakUnmetReason(ArmingInputs{SoakAttested: false}) == "" {
		t.Error("legacy SoakAttested=false with no path must refuse")
	}
}

var errReadFail = &readError{"permission denied"}

type readError struct{ s string }

func (e *readError) Error() string { return e.s }
