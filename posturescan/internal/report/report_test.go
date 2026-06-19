package report

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSeverityJSONRoundTrip(t *testing.T) {
	for _, s := range []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var got Severity
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got != s {
			t.Errorf("round trip %v -> %v", s, got)
		}
	}
}

func TestSeverityUnmarshalUnknown(t *testing.T) {
	var s Severity
	if err := json.Unmarshal([]byte(`"bogus"`), &s); err == nil {
		t.Error("expected error for unknown severity")
	}
}

func TestSummarizeCleanThreshold(t *testing.T) {
	tests := []struct {
		sev   Severity
		clean bool
	}{
		{SeverityInfo, true}, {SeverityLow, true},
		{SeverityMedium, false}, {SeverityHigh, false}, {SeverityCritical, false},
	}
	for _, tc := range tests {
		r := New("posturescan", "h", "rpm", time.Unix(0, 0), []Finding{{Severity: tc.sev}})
		if r.Summary.Clean != tc.clean {
			t.Errorf("sev %v clean=%v want %v", tc.sev, r.Summary.Clean, tc.clean)
		}
		wantExit := 0
		if !tc.clean {
			wantExit = 2
		}
		if r.ExitCode() != wantExit {
			t.Errorf("sev %v exit=%d want %d", tc.sev, r.ExitCode(), wantExit)
		}
	}
}

func TestSummarizeCounts(t *testing.T) {
	r := New("a", "h", "", time.Unix(0, 0), []Finding{
		{Severity: SeverityInfo}, {Severity: SeverityInfo}, {Severity: SeverityHigh},
	})
	if r.Summary.Total != 3 {
		t.Errorf("total=%d", r.Summary.Total)
	}
	if r.Summary.BySeverity["info"] != 2 || r.Summary.BySeverity["high"] != 1 {
		t.Errorf("bySeverity=%v", r.Summary.BySeverity)
	}
	if r.Summary.Worst != SeverityHigh {
		t.Errorf("worst=%v", r.Summary.Worst)
	}
}

func TestNewEmptyFindingsNonNil(t *testing.T) {
	r := New("posturescan", "h", "", time.Unix(0, 0), nil)
	if r.Findings == nil {
		t.Error("findings should be non-nil for clean JSON output")
	}
	if !r.Summary.Clean {
		t.Error("empty run should be clean")
	}
}

func TestEmitJournalPriorityPrefixes(t *testing.T) {
	r := New("posturescan", "h", "rpm", time.Unix(0, 0), []Finding{
		{Check: "sysctl", Severity: SeverityHigh, Title: "drift", Path: "kernel.yama.ptrace_scope", Technique: "T1068"},
		{Check: "a", Severity: SeverityInfo, Title: "ok"},
	})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<3>posturescan[sysctl]", "<6>posturescan[a]", "path=kernel.yama.ptrace_scope", "technique=T1068", "[summary]"} {
		if !strings.Contains(out, want) {
			t.Errorf("journal missing %q in:\n%s", want, out)
		}
	}
}

func TestEmitJournalSanitizesControlChars(t *testing.T) {
	// Path carries an attacker-influenced container name; a CR/LF in it must not
	// forge an extra journald record. Title and Technique are sanitized too.
	r := New("posturescan", "h", "", time.Unix(0, 0), []Finding{
		{
			Check:     "caps",
			Severity:  SeverityHigh,
			Title:     "stray cap\ngranted",
			Path:      "/evil\n<2>posturescan[forged] critical: pwned",
			Technique: "T1068\rINJECT",
		},
	})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// One finding + one summary line => exactly two newlines, no forged record.
	if n := strings.Count(out, "\n"); n != 2 {
		t.Errorf("want 2 lines (finding + summary), got %d:\n%q", n, out)
	}
	if strings.Contains(out, "[forged]") && strings.Contains(out, "<2>posturescan[forged]") {
		// The forged prefix must not sit at the start of its own line.
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "<2>posturescan[forged]") {
				t.Errorf("forged journald record was injected: %q", line)
			}
		}
	}
	if strings.ContainsAny(out[:len(out)-1], "\r") {
		t.Error("carriage return survived sanitization")
	}
}

func TestPostureSerializesWhenSet(t *testing.T) {
	r := New("posturescan", "h", "", time.Unix(0, 0), nil)
	r.Posture = &Posture{HardeningIndex: 60, TargetIndex: 100, Sysctls: []SysctlRow{
		{Key: "kernel.yama.ptrace_scope", Want: "2", Got: "0", Status: "DIFFERENT"},
	}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"hardening_index":60`) {
		t.Errorf("posture not serialized: %s", b)
	}
	// A report without posture must omit the key entirely. (Match the JSON key,
	// not the bare word — "posturescan" the tool name also contains "posture".)
	r2 := New("posturescan", "h", "", time.Unix(0, 0), nil)
	b2, _ := json.Marshal(r2)
	if strings.Contains(string(b2), `"posture"`) {
		t.Errorf("nil posture should be omitted: %s", b2)
	}
}

func TestEmitWebhookPostsJSON(t *testing.T) {
	var body []byte
	var auth, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ = io.ReadAll(req.Body)
		auth = req.Header.Get("Authorization")
		ctype = req.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New("posturescan", "h", "rpm", time.Unix(0, 0), []Finding{{Check: "sysctl", Severity: SeverityHigh, Title: "x"}})
	if err := EmitWebhook(context.Background(), srv.Client(), srv.URL, "Bearer t0k", r); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer t0k" {
		t.Errorf("auth=%q", auth)
	}
	if ctype != "application/json" {
		t.Errorf("content-type=%q", ctype)
	}
	var decoded Report
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if decoded.Tool != "posturescan" || len(decoded.Findings) != 1 {
		t.Errorf("decoded=%+v", decoded)
	}
}

func TestEmitWebhookEmptyURLIsNoop(t *testing.T) {
	if err := EmitWebhook(context.Background(), nil, "", "", New("a", "h", "", time.Unix(0, 0), nil)); err != nil {
		t.Errorf("empty url should be no-op, got %v", err)
	}
}

func TestEmitWebhookErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := EmitWebhook(context.Background(), srv.Client(), srv.URL, "", New("a", "h", "", time.Unix(0, 0), nil)); err == nil {
		t.Error("expected error on HTTP 500")
	}
}

func TestEmitWebhookRefusesRedirect(t *testing.T) {
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	err := EmitWebhook(context.Background(), redirector.Client(), redirector.URL, "Bearer secret",
		New("posturescan", "h", "", time.Unix(0, 0), nil))
	if err == nil {
		t.Error("a redirect from the collector should surface as an error, not be followed")
	}
	if followed {
		t.Error("posturescan followed the redirect — the token and report would leak")
	}
}
