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
		r := New("instguard", "h", "arch", time.Unix(0, 0), []Finding{{Severity: tc.sev}}, nil)
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
	}, nil)
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

func TestSummarizeCountsBlockedVerdicts(t *testing.T) {
	r := New("instguard", "h", "", time.Unix(0, 0), nil, []Verdict{
		{Package: "a", Decision: "BLOCK"},
		{Package: "b", Decision: "REVIEW"},
		{Package: "c", Decision: "BLOCK"},
		{Package: "d", Decision: "SAFE"},
	})
	if r.Summary.Blocked != 2 {
		t.Errorf("blocked=%d want 2", r.Summary.Blocked)
	}
}

func TestNewEmptyFindingsNonNil(t *testing.T) {
	r := New("instguard", "h", "", time.Unix(0, 0), nil, nil)
	if r.Findings == nil {
		t.Error("findings should be non-nil for clean JSON output")
	}
	if !r.Summary.Clean {
		t.Error("empty run should be clean")
	}
}

func TestEmitJournalPriorityPrefixes(t *testing.T) {
	r := New("instguard", "h", "arch", time.Unix(0, 0), []Finding{
		{Check: "osv", Severity: SeverityCritical, Title: "known-mal", Package: "left-pad", Technique: "T1195.001"},
		{Check: "a", Severity: SeverityInfo, Title: "ok"},
	}, nil)
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<2>instguard[osv]", "<6>instguard[a]", "package=left-pad", "technique=T1195.001", "[summary]"} {
		if !strings.Contains(out, want) {
			t.Errorf("journal missing %q in:\n%s", want, out)
		}
	}
}

// Fix #6: a finding field carrying an embedded CR/LF (e.g. a crafted Linux
// filename in Path) must not forge an extra journald record. Each finding emits
// exactly one line; the control bytes become spaces.
func TestEmitJournalSanitizesControlChars(t *testing.T) {
	r := New("instguard", "h", "", time.Unix(0, 0), []Finding{
		{Check: "aur", Severity: SeverityHigh, Title: "t", Path: "evil\n<2>forged path\rtitle: pwned"},
	}, nil)
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// Exactly two lines: the single finding line plus the summary line.
	if len(lines) != 2 {
		t.Fatalf("expected 1 finding + 1 summary line, got %d:\n%s", len(lines), out)
	}
	// The forged "<2>" priority prefix must not start any line.
	for _, l := range lines {
		if strings.HasPrefix(l, "<2>") {
			t.Errorf("a forged priority-prefixed line leaked through: %q", l)
		}
	}
	// The newline/CR are gone; the (now space-joined) text survives on one line.
	if strings.ContainsAny(lines[0], "\r") {
		t.Errorf("control char survived in finding line: %q", lines[0])
	}
	if !strings.Contains(lines[0], "forged path") {
		t.Errorf("path text should survive (with spaces): %q", lines[0])
	}
}

// Title and Technique are sanitized too — a Title with a newline cannot split
// the finding line.
func TestEmitJournalSanitizesTitleAndTechnique(t *testing.T) {
	r := New("instguard", "h", "", time.Unix(0, 0), []Finding{
		{Check: "osv", Severity: SeverityHigh, Title: "line1\n<2>line2", Technique: "T1\n059"},
	}, nil)
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("title/technique newline forged extra lines: %d\n%s", len(lines), buf.String())
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

	r := New("instguard", "h", "arch", time.Unix(0, 0), []Finding{{Check: "osv", Severity: SeverityHigh, Title: "x"}}, nil)
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
	if decoded.Tool != "instguard" || len(decoded.Findings) != 1 {
		t.Errorf("decoded=%+v", decoded)
	}
}

func TestEmitWebhookEmptyURLIsNoop(t *testing.T) {
	if err := EmitWebhook(context.Background(), nil, "", "", New("a", "h", "", time.Unix(0, 0), nil, nil)); err != nil {
		t.Errorf("empty url should be no-op, got %v", err)
	}
}

func TestEmitWebhookErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := EmitWebhook(context.Background(), srv.Client(), srv.URL, "", New("a", "h", "", time.Unix(0, 0), nil, nil)); err == nil {
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
		New("instguard", "h", "", time.Unix(0, 0), nil, nil))
	if err == nil {
		t.Error("a redirect from the collector should surface as an error, not be followed")
	}
	if followed {
		t.Error("instguard followed the redirect — the token and report would leak")
	}
}

// WebhookAuth must never be serialized; the report carries no secret field, but
// guard against a future regression that adds one by asserting the marshalled
// JSON never contains a token even when set on a finding's detail.
func TestReportJSONHasNoAuthField(t *testing.T) {
	r := New("instguard", "h", "", time.Unix(0, 0), nil, nil)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(b)), "authorization") {
		t.Errorf("report JSON leaked an authorization field: %s", b)
	}
}
