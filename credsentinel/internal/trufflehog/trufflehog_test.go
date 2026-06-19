package trufflehog

import (
	"context"
	"strings"
	"testing"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/runner"
)

const verifiedLine = `{"DetectorName":"AWS","Verified":true,"Raw":"AKIAIOSFODNN7EXAMPLE","SourceMetadata":{"Data":{"Filesystem":{"file":"/home/dev/.aws/credentials"}}}}`
const unverifiedLine = `{"DetectorName":"Generic","Verified":false,"Raw":"sometoken1234567890","SourceMetadata":{"Data":{"Filesystem":{"file":"/srv/repo/x"}}}}`

func TestParseNDJSONSkipsNoise(t *testing.T) {
	out := "starting trufflehog...\n" + verifiedLine + "\n\n{\"some\":\"log\"}\n" + unverifiedLine + "\n"
	rs := ParseNDJSON(out)
	if len(rs) != 2 {
		t.Fatalf("expected 2 results, got %d: %+v", len(rs), rs)
	}
	if rs[0].DetectorName != "AWS" || !rs[0].Verified {
		t.Errorf("first=%+v", rs[0])
	}
	if rs[0].file() != "/home/dev/.aws/credentials" {
		t.Errorf("file=%q", rs[0].file())
	}
}

func TestArgsVerifiedOnly(t *testing.T) {
	a := strings.Join(Args("/home/dev"), " ")
	for _, want := range []string{"filesystem /home/dev", "--json", "--results=verified"} {
		if !strings.Contains(a, want) {
			t.Errorf("args missing %q: %s", want, a)
		}
	}
}

func TestVerifiedHitIsCritical(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"trufflehog " + strings.Join(Args("/home/dev"), " "): {Stdout: verifiedLine + "\n", ExitCode: 183},
	}}
	fs := Scan(context.Background(), f, "/home/dev")
	if len(fs) != 1 || fs[0].Severity != report.SeverityCritical {
		t.Fatalf("verified hit must be Critical: %+v", fs)
	}
	if !strings.Contains(strings.ToLower(fs[0].Title), "rotate now") {
		t.Errorf("title should say rotate now: %q", fs[0].Title)
	}
	if strings.Contains(fs[0].Detail, "IOSFODNN7EXAMPLE") {
		t.Error("verified finding re-leaked the secret")
	}
}

func TestUnverifiedHitIsHigh(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"trufflehog " + strings.Join(Args("/srv"), " "): {Stdout: unverifiedLine + "\n", ExitCode: 0},
	}}
	fs := Scan(context.Background(), f, "/srv")
	if len(fs) != 1 || fs[0].Severity != report.SeverityHigh {
		t.Errorf("unverified hit should be High: %+v", fs)
	}
}

func TestScanMissingBinaryIsInfo(t *testing.T) {
	fs := Scan(context.Background(), &runner.Fake{}, "/home/dev")
	if len(fs) != 1 || fs[0].Severity != report.SeverityInfo {
		t.Errorf("missing trufflehog should be Info: %+v", fs)
	}
}

func TestScanCleanIsInfo(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"trufflehog " + strings.Join(Args("/home/dev"), " "): {Stdout: "scanned, nothing verified\n", ExitCode: 0},
	}}
	fs := Scan(context.Background(), f, "/home/dev")
	if len(fs) != 1 || fs[0].Severity != report.SeverityInfo {
		t.Errorf("clean scan should be Info: %+v", fs)
	}
}
