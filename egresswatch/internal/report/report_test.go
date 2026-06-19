package report

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSummarizeAndExitCode(t *testing.T) {
	clean := New("egresswatch", "h", time.Unix(0, 0), []Finding{
		{Check: "a", Severity: SeverityInfo},
		{Check: "b", Severity: SeverityLow},
	})
	if !clean.Summary.Clean || clean.ExitCode() != 0 {
		t.Errorf("info/low should be clean exit 0: %+v", clean.Summary)
	}
	if clean.Summary.Worst != SeverityLow {
		t.Errorf("worst=%v", clean.Summary.Worst)
	}

	dirty := New("egresswatch", "h", time.Unix(0, 0), []Finding{
		{Check: "a", Severity: SeverityLow},
		{Check: "b", Severity: SeverityHigh},
	})
	if dirty.Summary.Clean || dirty.ExitCode() != 2 {
		t.Errorf("high should be dirty exit 2: %+v", dirty.Summary)
	}
	if dirty.Summary.Worst != SeverityHigh {
		t.Errorf("worst=%v", dirty.Summary.Worst)
	}
	if dirty.Summary.BySeverity["high"] != 1 || dirty.Summary.BySeverity["low"] != 1 {
		t.Errorf("by_severity=%v", dirty.Summary.BySeverity)
	}
}

func TestNewNilFindings(t *testing.T) {
	r := New("egresswatch", "h", time.Unix(0, 0), nil)
	if r.Findings == nil {
		t.Error("findings should be non-nil empty slice for clean JSON")
	}
	if !r.Summary.Clean || r.Summary.Total != 0 {
		t.Errorf("empty report should be clean: %+v", r.Summary)
	}
}

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
			t.Errorf("roundtrip %v -> %v", s, got)
		}
	}
	var bad Severity
	if err := json.Unmarshal([]byte(`"nonsense"`), &bad); err == nil {
		t.Error("unknown severity should error")
	}
}

func TestEmitJournalPriorityPrefix(t *testing.T) {
	r := New("egresswatch", "h", time.Unix(0, 0), []Finding{
		{Check: "triage", Severity: SeverityCritical, Title: "implant", Path: "/proc/9", Technique: "T1205.002", Detail: "x"},
	})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<2>egresswatch[triage]") {
		t.Errorf("critical should carry priority prefix <2>: %q", out)
	}
	if !strings.Contains(out, "path=/proc/9") || !strings.Contains(out, "technique=T1205.002") {
		t.Errorf("journal line missing fields: %q", out)
	}
	if !strings.Contains(out, "<4>egresswatch[summary]") {
		t.Errorf("dirty summary should be warning priority: %q", out)
	}
}

// Regression: a finding's Title/Path/Technique can derive from attacker-controlled
// data (a comm name, an exe path). EmitJournal interpolates them bare, so newlines
// or control bytes would forge a second journald line. They must be sanitized to
// spaces, keeping each finding on exactly one line.
func TestEmitJournalSanitizesFields(t *testing.T) {
	r := New("egresswatch", "h", time.Unix(0, 0), []Finding{
		{
			Check:     "triage",
			Severity:  SeverityHigh,
			Title:     "evil\n<2>egresswatch[forged] fake: injected",
			Path:      "/proc/9/x\ty",
			Technique: "T1205\r.002",
			Detail:    "real\ndetail",
		},
	})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Exactly two lines: one finding line + one summary line. A forged newline in
	// any bare field would create a third.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("log-forgery: want 2 lines (finding+summary), got %d: %q", len(lines), out)
	}
	if strings.Contains(lines[0], "\t") || strings.Contains(lines[0], "\r") {
		t.Errorf("control chars must be scrubbed from the finding line: %q", lines[0])
	}
	// The forged-priority marker must not appear at the start of any line.
	if strings.Contains(lines[0], "egresswatch[forged]") && strings.Index(lines[0], "egresswatch[forged]") < strings.Index(lines[0], "evil") {
		t.Errorf("forged prefix escaped sanitization: %q", lines[0])
	}
	// Detail uses %q, so its newline is escaped, not raw — still single-line safe.
	if !strings.Contains(lines[0], `detail="real\ndetail"`) {
		t.Errorf("detail should be %%q-quoted: %q", lines[0])
	}
}

func TestEmitWebhookBlankURLNoop(t *testing.T) {
	if err := EmitWebhook(context.Background(), nil, "", "", New("egresswatch", "h", time.Unix(0, 0), nil)); err != nil {
		t.Errorf("blank url should be a no-op: %v", err)
	}
}

func TestEmitWebhookPostsJSON(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
		b, _ := readAll(req)
		gotBody = b
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := New("egresswatch", "host1", time.Unix(0, 0), []Finding{{Check: "egress", Severity: SeverityHigh}})
	if err := EmitWebhook(context.Background(), srv.Client(), srv.URL, "Bearer t", r); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer t" {
		t.Errorf("auth=%q", gotAuth)
	}
	if !strings.Contains(gotBody, `"tool":"egresswatch"`) || !strings.Contains(gotBody, `"host":"host1"`) {
		t.Errorf("body=%q", gotBody)
	}
}

func TestEmitWebhookDoesNotFollowRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "http://attacker.invalid/steal", http.StatusFound)
	}))
	defer srv.Close()
	err := EmitWebhook(context.Background(), srv.Client(), srv.URL, "Bearer t", New("egresswatch", "h", time.Unix(0, 0), nil))
	if err == nil {
		t.Error("a redirecting collector should surface as an error, not be followed")
	}
}

func readAll(req *http.Request) (string, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(req.Body)
	return buf.String(), err
}
