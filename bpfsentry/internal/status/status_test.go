package status

import (
	"context"
	"errors"
	"testing"

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/enumerate"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/report"
)

func countBy(findings []report.Finding, sev report.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func TestStatusFullVisibility(t *testing.T) {
	opts := Options{
		BaselinePath:   "/mnt/anchor/allowlist.json",
		BaselineExists: func(string) bool { return true },
		Enumerate: func(context.Context) (enumerate.Inventory, error) {
			return enumerate.Inventory{Programs: []enumerate.Program{{ID: 1}}}, nil
		},
	}
	f := Check(context.Background(), nil, opts)
	// All visibility lines should be Info: baseline present + enumeration up +
	// the OOB reminder.
	if countBy(f, report.SeverityLow) != 0 {
		t.Errorf("full visibility should have no Low findings: %+v", f)
	}
	if countBy(f, report.SeverityInfo) < 3 {
		t.Errorf("expected at least 3 Info lines, got %+v", f)
	}
}

func TestStatusNoBaselineIsLow(t *testing.T) {
	opts := Options{
		BaselinePath: "",
		Enumerate: func(context.Context) (enumerate.Inventory, error) {
			return enumerate.Inventory{}, nil
		},
	}
	f := Check(context.Background(), nil, opts)
	if countBy(f, report.SeverityLow) != 1 {
		t.Errorf("missing baseline should produce one Low finding: %+v", f)
	}
}

func TestStatusMissingBaselineFileIsLow(t *testing.T) {
	opts := Options{
		BaselinePath:   "/mnt/anchor/allowlist.json",
		BaselineExists: func(string) bool { return false },
		Enumerate: func(context.Context) (enumerate.Inventory, error) {
			return enumerate.Inventory{}, nil
		},
	}
	f := Check(context.Background(), nil, opts)
	if countBy(f, report.SeverityLow) != 1 {
		t.Errorf("missing baseline file should produce one Low finding: %+v", f)
	}
}

func TestStatusEnumerateUnavailableIsLow(t *testing.T) {
	opts := Options{
		BaselinePath:   "/x",
		BaselineExists: func(string) bool { return true },
		Enumerate: func(context.Context) (enumerate.Inventory, error) {
			return enumerate.Inventory{}, errors.New("bpftool not found")
		},
	}
	f := Check(context.Background(), nil, opts)
	if countBy(f, report.SeverityLow) != 1 {
		t.Errorf("unavailable enumeration should produce one Low finding: %+v", f)
	}
	foundTech := false
	for _, fd := range f {
		if fd.Technique == "T1562.001" {
			foundTech = true
		}
	}
	if !foundTech {
		t.Error("reduced-visibility finding should carry T1562.001")
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 5: "5", 42: "42", 1000: "1000", -7: "-7"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d)=%q want %q", in, got, want)
		}
	}
}
