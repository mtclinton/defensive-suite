package gitleaks

import (
	"context"
	"strings"
	"testing"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/runner"
)

const sampleReport = `[
  {
    "Description": "AWS Access Key",
    "File": "/srv/repo/config.tf",
    "RuleID": "aws-access-token",
    "StartLine": 12,
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "Match": "AKIAIOSFODNN7EXAMPLE"
  }
]`

func TestParseReportPopulated(t *testing.T) {
	fs, err := ParseReport(sampleReport)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != "aws-access-token" || fs[0].StartLine != 12 {
		t.Errorf("parsed=%+v", fs)
	}
}

func TestParseReportEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "null", "[]"} {
		fs, err := ParseReport(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
		}
		if len(fs) != 0 {
			t.Errorf("%q -> %+v", in, fs)
		}
	}
}

func TestParseReportMalformed(t *testing.T) {
	if _, err := ParseReport("{not json"); err == nil {
		t.Error("expected parse error")
	}
}

func TestArgsRequestsJSONToStdout(t *testing.T) {
	a := strings.Join(Args("/srv/repo"), " ")
	for _, want := range []string{"detect", "--source /srv/repo", "--no-git", "--report-format json", "--report-path -"} {
		if !strings.Contains(a, want) {
			t.Errorf("args missing %q: %s", want, a)
		}
	}
}

func TestScanFindingsRedacted(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"gitleaks " + strings.Join(Args("/srv/repo"), " "): {Stdout: sampleReport, ExitCode: 0},
	}}
	fs := Scan(context.Background(), f, "/srv/repo")
	if len(fs) != 1 || fs[0].Severity != report.SeverityHigh {
		t.Fatalf("findings=%+v", fs)
	}
	if strings.Contains(fs[0].Detail, "IOSFODNN7EXAMPLE") {
		t.Error("gitleaks finding re-leaked the secret")
	}
	if fs[0].Technique != "T1552.001" {
		t.Errorf("technique=%q", fs[0].Technique)
	}
}

func TestScanMissingBinaryIsInfo(t *testing.T) {
	fs := Scan(context.Background(), &runner.Fake{}, "/srv/repo")
	if len(fs) != 1 || fs[0].Severity != report.SeverityInfo {
		t.Errorf("missing gitleaks should be Info: %+v", fs)
	}
}

func TestScanCleanIsInfo(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"gitleaks " + strings.Join(Args("/srv/repo"), " "): {Stdout: "[]", ExitCode: 0},
	}}
	fs := Scan(context.Background(), f, "/srv/repo")
	if len(fs) != 1 || fs[0].Severity != report.SeverityInfo {
		t.Errorf("clean scan should be Info: %+v", fs)
	}
}
