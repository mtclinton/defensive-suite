package verdict

import (
	"testing"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

func TestDecideThresholds(t *testing.T) {
	cases := []struct {
		sev  report.Severity
		want string
	}{
		{report.SeverityInfo, Safe},
		{report.SeverityLow, Safe},
		{report.SeverityMedium, Review},
		{report.SeverityHigh, Block},
		{report.SeverityCritical, Block},
	}
	for _, tc := range cases {
		if got := decide(tc.sev); got != tc.want {
			t.Errorf("decide(%v)=%q want %q", tc.sev, got, tc.want)
		}
	}
}

func TestBuildPerPackageVerdicts(t *testing.T) {
	findings := []report.Finding{
		{Check: "osv", Severity: report.SeverityCritical, Package: "evil", Title: "MAL advisory"},
		{Check: "cooldown", Severity: report.SeverityMedium, Package: "fresh", Title: "too fresh"},
		{Check: "hooks", Severity: report.SeverityInfo, Package: "noisy", Title: "has install hook"},
	}
	pinned := map[string][]string{"evil": {"1.0.0"}, "fresh": {"2.0.0"}, "noisy": {"3.0.0"}, "clean": {"4.0.0"}}
	vs := Build(findings, pinned)

	got := map[string]report.Verdict{}
	for _, v := range vs {
		got[v.Package] = v
	}
	if got["evil"].Decision != Block {
		t.Errorf("evil=%+v want BLOCK", got["evil"])
	}
	if got["evil"].Version != "1.0.0" {
		t.Errorf("evil version=%q", got["evil"].Version)
	}
	if got["fresh"].Decision != Review {
		t.Errorf("fresh=%+v want REVIEW", got["fresh"])
	}
	if got["noisy"].Decision != Safe {
		t.Errorf("noisy(info only)=%+v want SAFE", got["noisy"])
	}
	if got["clean"].Decision != Safe {
		t.Errorf("clean(no findings)=%+v want SAFE", got["clean"])
	}
	// Reasons only collected for medium+.
	if len(got["evil"].Reasons) != 1 || got["evil"].Reasons[0] != "MAL advisory" {
		t.Errorf("evil reasons=%v", got["evil"].Reasons)
	}
	if len(got["noisy"].Reasons) != 0 {
		t.Errorf("noisy should have no review reasons: %v", got["noisy"].Reasons)
	}
}

func TestBuildProjectScope(t *testing.T) {
	findings := []report.Finding{
		{Check: "lockfile", Severity: report.SeverityHigh, Title: "no lockfile"}, // no Package
	}
	vs := Build(findings, nil)
	if len(vs) != 1 || vs[0].Package != ProjectScope || vs[0].Decision != Block {
		t.Errorf("project-scope verdict=%+v", vs)
	}
}

func TestBuildDeterministicOrder(t *testing.T) {
	vs := Build(nil, map[string][]string{"z": {"1"}, "a": {"1"}, "m": {"1"}})
	if len(vs) != 3 || vs[0].Package != "a" || vs[1].Package != "m" || vs[2].Package != "z" {
		t.Errorf("verdicts not sorted: %+v", vs)
	}
}

// Fix #1 (verdict honesty): a package resolved to two distinct versions names
// both of them on its single verdict.
func TestBuildMultiVersionRecordsAll(t *testing.T) {
	vs := Build(nil, map[string][]string{"evil": {"1.0.0", "6.6.6"}})
	if len(vs) != 1 {
		t.Fatalf("want one verdict, got %+v", vs)
	}
	if vs[0].Version != "1.0.0, 6.6.6" {
		t.Errorf("verdict should list every resolved version: %q", vs[0].Version)
	}
}

func TestAnyBlocked(t *testing.T) {
	if AnyBlocked([]report.Verdict{{Decision: Safe}, {Decision: Review}}) {
		t.Error("no block should be false")
	}
	if !AnyBlocked([]report.Verdict{{Decision: Safe}, {Decision: Block}}) {
		t.Error("a block should be true")
	}
}

func TestBuildDedupReasons(t *testing.T) {
	findings := []report.Finding{
		{Severity: report.SeverityHigh, Package: "p", Title: "same reason"},
		{Severity: report.SeverityHigh, Package: "p", Title: "same reason"},
	}
	vs := Build(findings, nil)
	if len(vs) != 1 || len(vs[0].Reasons) != 1 {
		t.Errorf("reasons should be deduped: %+v", vs)
	}
}
