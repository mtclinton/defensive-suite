package aide

import (
	"context"
	"testing"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

func TestParseCheckModern(t *testing.T) {
	out := `AIDE found differences between database and filesystem!!
Summary:
  Total number of entries:	1000
  Added entries:		3
  Removed entries:		1
  Changed entries:		5`
	s := ParseCheck(out)
	if s.Added != 3 || s.Removed != 1 || s.Changed != 5 || !s.Differences {
		t.Errorf("summary=%+v", s)
	}
}

func TestParseCheckOldFormat(t *testing.T) {
	s := ParseCheck("Added files: 2\nRemoved files: 0\nChanged files: 0")
	if s.Added != 2 || !s.Differences {
		t.Errorf("summary=%+v", s)
	}
}

func TestParseCheckClean(t *testing.T) {
	s := ParseCheck("AIDE, version 0.16\n### All files match AIDE database. Looks okay!")
	if s.Differences {
		t.Errorf("clean output should report no differences: %+v", s)
	}
}

func TestRunMissingAideIsInfo(t *testing.T) {
	findings := Run(context.Background(), &runner.Fake{}, "")
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("findings=%+v", findings)
	}
}

func TestRunDifferencesIsHigh(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"aide --check": {Stdout: "AIDE found differences between database and filesystem!!\nChanged entries:\t2\n", ExitCode: 4},
	}}
	findings := Run(context.Background(), f, "")
	if len(findings) != 1 || findings[0].Severity != report.SeverityHigh || findings[0].Technique != "T1565.001" {
		t.Errorf("findings=%+v", findings)
	}
}

func TestRunCleanIsInfo(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"aide --check": {Stdout: "All files match AIDE database.", ExitCode: 0},
	}}
	findings := Run(context.Background(), f, "")
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("findings=%+v", findings)
	}
}
