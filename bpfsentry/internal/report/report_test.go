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
		r := New("bpfsentry", "h", "ubuntu", time.Unix(0, 0), []Finding{{Severity: tc.sev}})
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
	r := New("bpfsentry", "h", "", time.Unix(0, 0), nil)
	if r.Findings == nil {
		t.Error("findings should be non-nil for clean JSON output")
	}
	if !r.Summary.Clean {
		t.Error("empty run should be clean")
	}
}

func TestEmitJournalPriorityPrefixes(t *testing.T) {
	r := New("bpfsentry", "h", "ubuntu", time.Unix(0, 0), []Finding{
		{Check: "diff", Severity: SeverityCritical, Title: "hidden program", Path: "kprobe/sys_bpf", Technique: "T1014"},
		{Check: "a", Severity: SeverityInfo, Title: "ok"},
	})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<2>bpfsentry[diff]", "<6>bpfsentry[a]", "path=kprobe/sys_bpf", "technique=T1014", "[summary]"} {
		if !strings.Contains(out, want) {
			t.Errorf("journal missing %q in:\n%s", want, out)
		}
	}
}

func TestEmitJournalSanitizesLogForgery(t *testing.T) {
	// A finding field carrying attacker-controlled bytes (a BPF program name
	// resolves into Path/Title) must not be able to inject a forged journal line
	// via embedded CR/LF, nor smuggle a tab/control character.
	r := New("bpfsentry", "h", "", time.Unix(0, 0), []Finding{{
		Check:     "helpers",
		Severity:  SeverityHigh,
		Title:     "evil\nprog\r<2>bpfsentry[forged] critical: pwned",
		Path:      "spy\n@__x64_sys_bpf",
		Technique: "T1014\nINJECT",
	}})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// The only lines that may begin with a priority prefix are the one real
	// finding line and the summary line — never an injected one.
	priLines := 0
	for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.HasPrefix(ln, "<") {
			priLines++
		}
	}
	if priLines != 2 {
		t.Errorf("expected exactly 2 priority-prefixed lines (finding + summary), got %d in:\n%s", priLines, out)
	}
	if strings.Contains(out, "\n<2>bpfsentry[forged]") {
		t.Errorf("forged line was injected:\n%s", out)
	}
	// No raw CR/LF/tab from the fields should survive into the rendered line.
	if strings.Contains(out, "evil\nprog") || strings.Contains(out, "prog\r") || strings.Contains(out, "spy\n@") {
		t.Errorf("control characters survived sanitization:\n%q", out)
	}
	// The sanitized text (spaces in place of the control chars) is still present.
	if !strings.Contains(out, "evil prog ") {
		t.Errorf("sanitized title text missing:\n%s", out)
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

	r := New("bpfsentry", "h", "ubuntu", time.Unix(0, 0), []Finding{{Check: "diff", Severity: SeverityHigh, Title: "x"}})
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
	if decoded.Tool != "bpfsentry" || len(decoded.Findings) != 1 {
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
		New("bpfsentry", "h", "", time.Unix(0, 0), nil))
	if err == nil {
		t.Error("a redirect from the collector should surface as an error, not be followed")
	}
	if followed {
		t.Error("bpfsentry followed the redirect — the token and report would leak")
	}
}
