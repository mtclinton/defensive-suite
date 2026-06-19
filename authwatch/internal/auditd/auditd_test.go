package auditd

import (
	"context"
	"testing"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

func TestParseList(t *testing.T) {
	out := `-w /etc/ld.so.preload -p wa -k authwatch_ldpreload
-w /etc/pam.d -p wa -k authwatch_pam
-a always,exit -F arch=b64 -S execve -k exec
No rules`
	rules := ParseList(out)
	if len(rules) != 2 {
		t.Fatalf("rules=%+v", rules)
	}
	if rules[0].Path != "/etc/ld.so.preload" || rules[0].Key != "authwatch_ldpreload" || rules[0].Perms != "wa" {
		t.Errorf("rule0=%+v", rules[0])
	}
}

func TestMissingWatchesNormalizesTrailingSlash(t *testing.T) {
	loaded := []WatchRule{
		{Path: "/etc/ld.so.preload", Perms: "wa", Key: "x"},
		{Path: "/etc/pam.d", Perms: "wa", Key: "y"}, // no trailing slash; expected has one
	}
	missing := MissingWatches(loaded, ExpectedWatches)
	for _, m := range missing {
		if normalize(m.Path) == "/etc/pam.d" || normalize(m.Path) == "/etc/ld.so.preload" {
			t.Errorf("%s should be considered present despite trailing-slash difference", m.Path)
		}
	}
	if len(missing) != 2 {
		t.Errorf("expected sshd_config + root ssh missing, got %+v", missing)
	}
}

func TestCheckAllLoadedIsInfo(t *testing.T) {
	var lines string
	for _, e := range ExpectedWatches {
		lines += "-w " + e.Path + " -p " + e.Perms + " -k " + e.Key + "\n"
	}
	f := &runner.Fake{Responses: map[string]runner.Result{"auditctl -l": {Stdout: lines}}}
	findings := Check(context.Background(), f)
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("findings=%+v", findings)
	}
}

func TestCheckMissingAreLow(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"auditctl -l": {Stdout: "-w /etc/ld.so.preload -p wa -k authwatch_ldpreload\n"},
	}}
	findings := Check(context.Background(), f)
	if len(findings) != 3 {
		t.Fatalf("expected 3 missing watches, got %+v", findings)
	}
	for _, fd := range findings {
		if fd.Severity != report.SeverityLow {
			t.Errorf("missing watch should be low severity: %+v", fd)
		}
	}
}

func TestCheckAuditctlAbsentIsLow(t *testing.T) {
	findings := Check(context.Background(), &runner.Fake{})
	if len(findings) != 1 || findings[0].Severity != report.SeverityLow {
		t.Errorf("findings=%+v", findings)
	}
}

func TestMissingWatchesFlagsWeakenedPerms(t *testing.T) {
	var loaded []WatchRule
	for _, e := range ExpectedWatches {
		perms := e.Perms
		if e.Path == "/etc/ld.so.preload" {
			perms = "r" // downgraded from wa
		}
		loaded = append(loaded, WatchRule{Path: e.Path, Perms: perms, Key: e.Key})
	}
	missing := MissingWatches(loaded, ExpectedWatches)
	if len(missing) != 1 || missing[0].Path != "/etc/ld.so.preload" {
		t.Errorf("a watch loaded with weakened perms should be reported: %+v", missing)
	}
}

func TestCheckNonZeroExitIsUnavailable(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"auditctl -l": {Stdout: "", Stderr: "permission denied", ExitCode: 1},
	}}
	findings := Check(context.Background(), f)
	if len(findings) != 1 || findings[0].Severity != report.SeverityLow {
		t.Errorf("non-zero auditctl exit must be one Low finding, not 'all missing': %+v", findings)
	}
}
