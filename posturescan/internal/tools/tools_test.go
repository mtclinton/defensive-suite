package tools

import (
	"context"
	"testing"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
	"github.com/mtclinton/defensive-suite/posturescan/internal/runner"
)

func TestParseLynisIndex(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
		ok   bool
	}{
		{"human", "  Hardening index : 67 [############        ]\n", 67, true},
		{"report.dat", "hardening_index=82\n", 82, true},
		{"mixed case", "HARDENING INDEX : 55", 55, true},
		{"absent", "nothing here\n", 0, false},
		// A "hardening index :" line with nothing after the colon must not panic
		// (Fields("")[0]); it is simply skipped, and a later valid line still wins.
		{"empty after colon", "Hardening index :\n", 0, false},
		{"empty colon then valid", "Hardening index :   \nhardening_index=71\n", 71, true},
	}
	for _, c := range cases {
		got, ok := ParseLynisIndex(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %d,%v want %d,%v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestLynisSeverityBands(t *testing.T) {
	cases := []struct {
		idx string
		sev report.Severity
	}{
		{"45", report.SeverityHigh},
		{"60", report.SeverityMedium},
		{"90", report.SeverityInfo},
	}
	for _, c := range cases {
		f := &runner.Fake{Responses: map[string]runner.Result{
			"lynis audit system --quiet --no-colors": {Stdout: "Hardening index : " + c.idx + " [###]"},
		}}
		fs := Lynis(context.Background(), f)
		if len(fs) != 1 || fs[0].Severity != c.sev {
			t.Errorf("idx=%s sev=%v want %v", c.idx, fs[0].Severity, c.sev)
		}
	}
}

func TestLynisAbsent(t *testing.T) {
	fs := Lynis(context.Background(), &runner.Fake{})
	if len(fs) != 1 || fs[0].Severity != report.SeverityInfo {
		t.Errorf("absent lynis should be info skip, got %+v", fs)
	}
}

func TestParseOscapResults(t *testing.T) {
	out := `Title   Ensure ptrace scope
Rule    xccdf_org.ssgproject...
Result  pass

Title   Ensure bpf disabled
Result  fail

Title   N/A on container
Result  notapplicable

Result  error
`
	r := ParseOscapResults(out)
	if r.Pass != 1 || r.Fail != 1 || r.Error != 1 || r.Total != 3 {
		t.Errorf("oscap tally=%+v", r)
	}
}

func TestOscapSkippedWithoutContent(t *testing.T) {
	fs := Oscap(context.Background(), &runner.Fake{}, "", "")
	if len(fs) != 1 || fs[0].Severity != report.SeverityInfo {
		t.Errorf("no content should skip at info, got %+v", fs)
	}
}

func TestOscapScoring(t *testing.T) {
	out := "Result pass\nResult pass\nResult fail\nResult fail\n" // 50% pass
	f := &runner.Fake{Responses: map[string]runner.Result{
		"oscap xccdf eval --profile cis /ds.xml": {Stdout: out, ExitCode: 2},
	}}
	fs := Oscap(context.Background(), f, "/ds.xml", "cis")
	if len(fs) != 1 || fs[0].Severity != report.SeverityHigh {
		t.Errorf("50%% pass should be High, got %+v", fs)
	}
}

func TestParseSystemdSecurity(t *testing.T) {
	out := `UNIT                        EXPOSURE PREDICATE HAPPY
sshd.service                     9.6 UNSAFE    :(
systemd-journald.service         4.2 MEDIUM    😐
chronyd.service                  2.1 OK        🙂
garbage line
`
	rows := ParseSystemdSecurity(out)
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d: %+v", len(rows), rows)
	}
	if rows[0].Unit != "sshd.service" || rows[0].Level != "UNSAFE" || rows[0].Exposure != 9.6 {
		t.Errorf("row0=%+v", rows[0])
	}
}

func TestSystemdSecurityFindings(t *testing.T) {
	out := "UNIT EXPOSURE PREDICATE HAPPY\nsshd.service 9.6 UNSAFE :(\nfoo.service 6.5 EXPOSED :|\nbar.service 1.0 OK :)\n"
	f := &runner.Fake{Responses: map[string]runner.Result{
		"systemd-analyze security --no-pager": {Stdout: out},
	}}
	fs := SystemdSecurity(context.Background(), f)
	var med, low, info int
	for _, x := range fs {
		switch x.Severity {
		case report.SeverityMedium:
			med++
		case report.SeverityLow:
			low++
		case report.SeverityInfo:
			info++
		}
	}
	if med != 1 || low != 1 || info != 1 {
		t.Errorf("severity counts med=%d low=%d info=%d (%+v)", med, low, info, fs)
	}
}

func TestSystemdSecurityAbsent(t *testing.T) {
	fs := SystemdSecurity(context.Background(), &runner.Fake{})
	if len(fs) != 1 || fs[0].Severity != report.SeverityInfo {
		t.Errorf("absent tool should be info skip, got %+v", fs)
	}
}
