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
		r := New("credsentinel", "h", "rpm", time.Unix(0, 0), []Finding{{Severity: tc.sev}})
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
		{Severity: SeverityInfo}, {Severity: SeverityInfo}, {Severity: SeverityCritical},
	})
	if r.Summary.Total != 3 {
		t.Errorf("total=%d", r.Summary.Total)
	}
	if r.Summary.BySeverity["info"] != 2 || r.Summary.BySeverity["critical"] != 1 {
		t.Errorf("bySeverity=%v", r.Summary.BySeverity)
	}
	if r.Summary.Worst != SeverityCritical {
		t.Errorf("worst=%v", r.Summary.Worst)
	}
}

func TestNewEmptyFindingsNonNil(t *testing.T) {
	r := New("credsentinel", "h", "", time.Unix(0, 0), nil)
	if r.Findings == nil {
		t.Error("findings should be non-nil for clean JSON output")
	}
	if !r.Summary.Clean {
		t.Error("empty run should be clean")
	}
}

func TestEmitJournalPriorityPrefixes(t *testing.T) {
	r := New("credsentinel", "h", "rpm", time.Unix(0, 0), []Finding{
		{Check: "trufflehog", Severity: SeverityCritical, Title: "verified live AWS key", Path: "/p", Technique: "T1552.001"},
		{Check: "honeytoken", Severity: SeverityInfo, Title: "deployed and quiet"},
	})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<2>credsentinel[trufflehog]", "<6>credsentinel[honeytoken]", "path=/p", "technique=T1552.001", "[summary]"} {
		if !strings.Contains(out, want) {
			t.Errorf("journal missing %q in:\n%s", want, out)
		}
	}
}

// FIX #5: a finding field (Path/Title/Technique) can carry attacker-controlled
// CR/LF (e.g. a scanned file name or decoy path with an embedded newline). Written
// raw into the one-line-per-finding journal it forges an extra log line. After
// sanitize, one finding must stay exactly one journal line (plus the summary).
func TestEmitJournalSanitizesControlChars(t *testing.T) {
	r := New("credsentinel", "h", "", time.Unix(0, 0), []Finding{{
		Check:     "targets",
		Severity:  SeverityHigh,
		Title:     "line1\nFORGED <2>credsentinel[forged] critical: injected",
		Path:      "/home/u/evil\nname",
		Technique: "T1552.001\r<6>forged",
	}})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// One finding line + one summary line == 2 newlines total. A CR/LF that slipped
	// through would add lines.
	if n := strings.Count(out, "\n"); n != 2 {
		t.Errorf("expected 2 lines (finding + summary), got %d:\n%q", n, out)
	}
	if strings.Contains(out, "\r") {
		t.Errorf("carriage return survived sanitize:\n%q", out)
	}
	// The forged-line payload must remain on the single finding line, spaces in
	// place of the control bytes — never at column 0 as its own line.
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.HasPrefix(line, "FORGED") || strings.HasPrefix(line, "<2>credsentinel[forged]") {
			t.Errorf("a forged log line was injected: %q", line)
		}
	}
	// The benign text on either side of the injected newline should survive.
	if !strings.Contains(out, "line1 FORGED") {
		t.Errorf("sanitized title should join with a space, got:\n%q", out)
	}
}

func TestEmitWebhookPostsJSON(t *testing.T) {
	var body []byte
	var auth, ctype, ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ = io.ReadAll(req.Body)
		auth = req.Header.Get("Authorization")
		ctype = req.Header.Get("Content-Type")
		ua = req.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New("credsentinel", "h", "rpm", time.Unix(0, 0), []Finding{{Check: "gitleaks", Severity: SeverityHigh, Title: "x"}})
	if err := EmitWebhook(context.Background(), srv.Client(), srv.URL, "Bearer t0k", r); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer t0k" {
		t.Errorf("auth=%q", auth)
	}
	if ctype != "application/json" {
		t.Errorf("content-type=%q", ctype)
	}
	if ua != "credsentinel" {
		t.Errorf("user-agent=%q", ua)
	}
	var decoded Report
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if decoded.Tool != "credsentinel" || len(decoded.Findings) != 1 {
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
		New("credsentinel", "h", "", time.Unix(0, 0), nil))
	if err == nil {
		t.Error("a redirect from the collector should surface as an error, not be followed")
	}
	if followed {
		t.Error("credsentinel followed the redirect — the token and report would leak")
	}
}
