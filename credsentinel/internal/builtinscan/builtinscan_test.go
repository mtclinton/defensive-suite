package builtinscan

import (
	"strings"
	"testing"

	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
)

func TestScanAWSAccessKey(t *testing.T) {
	ms := ScanText("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
	if !hasRule(ms, "aws-access-key-id") {
		t.Errorf("AWS access key not detected: %+v", ms)
	}
	for _, m := range ms {
		if strings.Contains(m.Redacted, "IOSFODNN7EXAMPLE") {
			t.Error("redaction failed — full secret in match")
		}
	}
}

func TestScanAWSSecretKey(t *testing.T) {
	ms := ScanText("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
	if !hasRule(ms, "aws-secret-access-key") {
		t.Errorf("AWS secret key not detected: %+v", ms)
	}
}

func TestScanPrivateKeyPEM(t *testing.T) {
	for _, hdr := range []string{
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
	} {
		ms := ScanText(hdr + "\nMIIEv...\n")
		if !hasRule(ms, "private-key-pem") {
			t.Errorf("PEM header %q not detected", hdr)
		}
		if ms[0].Severity != report.SeverityHigh {
			t.Errorf("PEM should be High, got %v", ms[0].Severity)
		}
	}
}

func TestScanProviderTokens(t *testing.T) {
	cases := map[string]string{
		"github-token":   "token: ghp_1234567890abcdefghijklmnopqrstuvwx",
		"npm-token":      "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789",
		"slack-token":    "xoxb-2468013579-abcdefghijkl",
		"google-api-key": "key=AIzaSyA1234567890abcdefghijklmnopqrstuv",
	}
	for rule, text := range cases {
		ms := ScanText(text)
		if !hasRule(ms, rule) {
			t.Errorf("%s not detected in %q: %+v", rule, text, ms)
		}
	}
}

func TestHighEntropyTokenFlagged(t *testing.T) {
	// A long, mixed-class random token assigned to a secret-ish key.
	ms := ScanText("client_secret = \"a8Kf93Lm2Qx7Zb1Nc4Vp6Rt0Yw5Hd8Sg3Jk\"\n")
	if !hasRule(ms, "high-entropy-token") {
		t.Errorf("high-entropy token not flagged: %+v", ms)
	}
}

func TestLowEntropyNotFlagged(t *testing.T) {
	// Paths, versions, and repeated chars must NOT trip the entropy heuristic —
	// this is the false-positive floor that keeps the fallback usable.
	clean := []string{
		"path = /usr/local/lib/python3.11/site-packages\n",
		"password = aaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
		"version = 1.2.3.4.5.6.7.8.9.10.11.12.13\n",
		"comment = this is a normal english sentence value here\n",
	}
	for _, c := range clean {
		if ms := ScanText(c); hasRule(ms, "high-entropy-token") {
			t.Errorf("false positive on %q: %+v", c, ms)
		}
	}
}

func TestCleanFileNoMatches(t *testing.T) {
	if ms := ScanText("# just a config\nname = myapp\nport = 8080\n"); len(ms) != 0 {
		t.Errorf("clean file produced matches: %+v", ms)
	}
}

func TestNoDoubleFlagProviderKey(t *testing.T) {
	// An AWS secret key line also matches the assignment heuristic; ensure it is
	// reported once by the precise rule, not twice.
	ms := ScanText("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
	n := 0
	for _, m := range ms {
		if m.Line == 1 {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected one finding for the secret line, got %d: %+v", n, ms)
	}
}

func TestFindingsForCarryMetadata(t *testing.T) {
	ms := ScanText("AKIAIOSFODNN7EXAMPLE\n")
	fs := FindingsFor("/home/x/.aws/credentials", "AWS credentials", ms)
	if len(fs) != 1 {
		t.Fatalf("findings=%+v", fs)
	}
	if fs[0].Check != "builtinscan" || fs[0].Path != "/home/x/.aws/credentials" {
		t.Errorf("finding=%+v", fs[0])
	}
	if !strings.Contains(fs[0].Detail, "kind=AWS credentials") {
		t.Errorf("kind missing from detail: %q", fs[0].Detail)
	}
	if fs[0].Technique != "T1552.001" {
		t.Errorf("technique=%q", fs[0].Technique)
	}
}

func TestEntropyAndClassMix(t *testing.T) {
	if shannonEntropy("aaaa") != 0 {
		t.Error("uniform string should have zero entropy")
	}
	if classMix("Abc123!") != 4 {
		t.Errorf("classMix=%d, want 4", classMix("Abc123!"))
	}
	if classMix("abcdef") != 1 {
		t.Errorf("single-class classMix=%d, want 1", classMix("abcdef"))
	}
}

func hasRule(ms []Match, rule string) bool {
	for _, m := range ms {
		if m.Rule == rule {
			return true
		}
	}
	return false
}
