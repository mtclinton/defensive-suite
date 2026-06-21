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

// The correlation-layer fields (Confidence, Related) must survive a JSON round
// trip so a correlated finding's confidence and lineage reach the dashboard.
func TestFindingConfidenceRelatedRoundTrip(t *testing.T) {
	in := Finding{
		Check: "realtime.correlated", Severity: SeverityCritical,
		Title: "suspicious process then connected out", Technique: "T1071",
		Confidence: "high",
		Related:    []string{"base: execution from a staging directory", "dst=1.2.3.4:443"},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Finding
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Confidence != "high" {
		t.Errorf("confidence=%q (want high)", out.Confidence)
	}
	if len(out.Related) != 2 || out.Related[1] != "dst=1.2.3.4:443" {
		t.Errorf("related=%v", out.Related)
	}
}

// A finding that sets neither field must emit no confidence/related keys, so
// existing findings/tools are byte-for-byte unaffected (omitempty).
func TestFindingOmitsEmptyCorrelationFields(t *testing.T) {
	b, err := json.Marshal(Finding{Check: "c", Severity: SeverityInfo, Title: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Contains(s, "confidence") || strings.Contains(s, "related") {
		t.Errorf("empty correlation fields must be omitted: %s", s)
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
		r := New("authwatch", "h", "rpm", time.Unix(0, 0), []Finding{{Severity: tc.sev}})
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
	r := New("authwatch", "h", "", time.Unix(0, 0), nil)
	if r.Findings == nil {
		t.Error("findings should be non-nil for clean JSON output")
	}
	if !r.Summary.Clean {
		t.Error("empty run should be clean")
	}
}

func TestEmitJournalPriorityPrefixes(t *testing.T) {
	r := New("authwatch", "h", "rpm", time.Unix(0, 0), []Finding{
		{Check: "pam", Severity: SeverityCritical, Title: "unowned", Path: "/p", Technique: "T1556.003"},
		{Check: "a", Severity: SeverityInfo, Title: "ok"},
	})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<2>authwatch[pam]", "<6>authwatch[a]", "path=/p", "technique=T1556.003", "[summary]"} {
		if !strings.Contains(out, want) {
			t.Errorf("journal missing %q in:\n%s", want, out)
		}
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

	r := New("authwatch", "h", "rpm", time.Unix(0, 0), []Finding{{Check: "pam", Severity: SeverityHigh, Title: "x"}})
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
	if decoded.Tool != "authwatch" || len(decoded.Findings) != 1 {
		t.Errorf("decoded=%+v", decoded)
	}
}

func TestEmitWebhookEmptyURLIsNoop(t *testing.T) {
	if err := EmitWebhook(context.Background(), nil, "", "", New("a", "h", "", time.Unix(0, 0), nil)); err != nil {
		t.Errorf("empty url should be no-op, got %v", err)
	}
}

// EmitWebhookBytes POSTs the supplied bytes VERBATIM (the spool replays the exact
// stored body), sets auth + content-type, and a blank URL is a no-op.
func TestEmitWebhookBytesPostsVerbatim(t *testing.T) {
	var body []byte
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ = io.ReadAll(req.Body)
		auth = req.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	raw := []byte(`{"tool":"agent","custom":true}`)
	if err := EmitWebhookBytes(context.Background(), srv.Client(), srv.URL, "Bearer k", raw); err != nil {
		t.Fatal(err)
	}
	if string(body) != string(raw) {
		t.Errorf("body should be sent verbatim: got %q want %q", body, raw)
	}
	if auth != "Bearer k" {
		t.Errorf("auth=%q", auth)
	}
	if err := EmitWebhookBytes(context.Background(), nil, "", "", raw); err != nil {
		t.Errorf("blank url should be a no-op, got %v", err)
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
		New("authwatch", "h", "", time.Unix(0, 0), nil))
	if err == nil {
		t.Error("a redirect from the collector should surface as an error, not be followed")
	}
	if followed {
		t.Error("authwatch followed the redirect — the token and report would leak")
	}
}

func TestEmitJournalSanitizesControlChars(t *testing.T) {
	r := New("authwatch", "h", "rpm", time.Unix(0, 0), []Finding{
		{Check: "pam", Severity: SeverityHigh, Title: "t",
			Path: "/tmp/evil\n<2>authwatch[forged] critical: injected record"},
	})
	var buf bytes.Buffer
	if err := EmitJournal(&buf, r); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 { // one finding line + one summary line, no forged third
		t.Errorf("control char in Path forged extra line(s); got %d lines:\n%s", len(lines), buf.String())
	}
}

// A Finding without AutoMeta must marshal WITHOUT an auto_meta key (omitempty
// pointer), so every existing finding and the collector are byte-for-byte
// unaffected by the new agent-internal field.
func TestFindingAutoMetaOmitEmpty(t *testing.T) {
	f := Finding{Check: "realtime.exec", Severity: SeverityMedium, Title: "x"}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "auto_meta") {
		t.Errorf("a finding with no AutoMeta must omit auto_meta: %s", b)
	}
}

// When set, AutoMeta marshals/round-trips its typed identity fields.
func TestFindingAutoMetaRoundTrip(t *testing.T) {
	when := time.Date(2026, 6, 20, 12, 0, 1, 0, time.UTC)
	f := Finding{
		Check:    "realtime.correlated",
		Severity: SeverityCritical,
		Title:    "c",
		AutoMeta: &AutoMeta{ExecID: "X", Pid: 1337, DetectedAt: when, Dst: "8.8.8.8", DstPort: 443},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "auto_meta") {
		t.Errorf("a finding WITH AutoMeta must include auto_meta: %s", b)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.AutoMeta == nil || back.AutoMeta.ExecID != "X" || back.AutoMeta.Pid != 1337 ||
		!back.AutoMeta.DetectedAt.Equal(when) || back.AutoMeta.Dst != "8.8.8.8" || back.AutoMeta.DstPort != 443 {
		t.Errorf("AutoMeta round-trip wrong: %+v", back.AutoMeta)
	}
}
