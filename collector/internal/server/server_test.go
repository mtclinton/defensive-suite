package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtclinton/defensive-suite/collector/internal/store"
)

func newTestServer(t *testing.T, token string, maxBody int64) *Server {
	t.Helper()
	st, err := store.New(t.TempDir(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if maxBody == 0 {
		maxBody = 1 << 20
	}
	return New(st, token, maxBody, []byte("<!doctype html><title>dash</title>"))
}

func do(s *Server, method, target, body, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

const validReport = `{"tool":"authwatch","host":"h","findings":[{"check":"pam","severity":"critical","title":"unowned PAM module"}]}`

func TestIngestRequiresToken(t *testing.T) {
	s := newTestServer(t, "", 0) // no token configured → fail closed
	if rr := do(s, "POST", "/ingest", validReport, "Bearer x"); rr.Code != http.StatusServiceUnavailable {
		t.Errorf("no-token server should 503, got %d", rr.Code)
	}
}

func TestIngestAuth(t *testing.T) {
	s := newTestServer(t, "secret", 0)
	if rr := do(s, "POST", "/ingest", validReport, ""); rr.Code != http.StatusUnauthorized {
		t.Errorf("missing auth should 401, got %d", rr.Code)
	}
	if rr := do(s, "POST", "/ingest", validReport, "Bearer wrong"); rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong token should 401, got %d", rr.Code)
	}
	if rr := do(s, "POST", "/ingest", validReport, "Bearer secret"); rr.Code != http.StatusAccepted {
		t.Errorf("valid ingest should 202, got %d (%s)", rr.Code, rr.Body)
	}
}

func TestIngestBadBodyAndMethod(t *testing.T) {
	s := newTestServer(t, "secret", 0)
	if rr := do(s, "POST", "/ingest", "{not json", "Bearer secret"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad json should 400, got %d", rr.Code)
	}
	if rr := do(s, "POST", "/ingest", `{"host":"h"}`, "Bearer secret"); rr.Code != http.StatusBadRequest {
		t.Errorf("missing tool should 400, got %d", rr.Code)
	}
	if rr := do(s, "GET", "/ingest", "", ""); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /ingest should 405, got %d", rr.Code)
	}
}

func TestIngestOversizedBodyRejected(t *testing.T) {
	s := newTestServer(t, "secret", 16) // 16-byte cap
	if rr := do(s, "POST", "/ingest", validReport, "Bearer secret"); rr.Code == http.StatusAccepted {
		t.Errorf("oversized body should not be accepted, got %d", rr.Code)
	}
}

func TestFindingsAndSummaryReflectIngest(t *testing.T) {
	s := newTestServer(t, "secret", 0)
	if rr := do(s, "POST", "/ingest", validReport, "Bearer secret"); rr.Code != http.StatusAccepted {
		t.Fatalf("ingest failed: %d", rr.Code)
	}
	rr := do(s, "GET", "/api/findings", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("findings status %d", rr.Code)
	}
	var fs []store.Finding
	if err := json.Unmarshal(rr.Body.Bytes(), &fs); err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Severity != "critical" || fs[0].Tool != "authwatch" {
		t.Errorf("findings=%+v", fs)
	}
	rr = do(s, "GET", "/api/summary", "", "")
	var sum store.Summary
	if err := json.Unmarshal(rr.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Findings != 1 || sum.Worst != "critical" || sum.Clean {
		t.Errorf("summary=%+v", sum)
	}
}

func TestDashboardAndHealth(t *testing.T) {
	s := newTestServer(t, "secret", 0)
	rr := do(s, "GET", "/", "", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<title>dash</title>") {
		t.Errorf("dashboard not served: %d %q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("dashboard content-type=%q", ct)
	}
	if rr := do(s, "GET", "/healthz", "", ""); rr.Code != http.StatusOK || rr.Body.String() != "ok\n" {
		t.Errorf("healthz=%d %q", rr.Code, rr.Body.String())
	}
	if rr := do(s, "GET", "/no-such-path", "", ""); rr.Code != http.StatusNotFound {
		t.Errorf("unknown path should 404, got %d", rr.Code)
	}
}

func TestEmptyFindingsIsJSONArray(t *testing.T) {
	s := newTestServer(t, "secret", 0)
	rr := do(s, "GET", "/api/findings", "", "")
	if strings.TrimSpace(rr.Body.String()) != "[]" {
		t.Errorf("empty findings should be [], got %q", rr.Body.String())
	}
}
