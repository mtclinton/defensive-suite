package respond

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler(t *testing.T, token string, dryRun bool, fake *FakeExecutor) *Handler {
	t.Helper()
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), dryRun, testGuards(), fixedClock())
	return NewHandler(r, token, 0)
}

func doReq(h *Handler, method, target, body, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

const killBody = `{"action":"kill","target":"1234","reason":"r","actor":"max"}`

func TestHTTPHealthz(t *testing.T) {
	h := newTestHandler(t, "tok", true, &FakeExecutor{})
	rr := doReq(h, "GET", "/healthz", "", "")
	if rr.Code != http.StatusOK || rr.Body.String() != "ok\n" {
		t.Errorf("healthz=%d %q", rr.Code, rr.Body.String())
	}
}

func TestHTTPRespondAuth(t *testing.T) {
	h := newTestHandler(t, "secret", true, &FakeExecutor{})
	if rr := doReq(h, "POST", "/respond", killBody, ""); rr.Code != http.StatusUnauthorized {
		t.Errorf("missing auth should 401, got %d", rr.Code)
	}
	if rr := doReq(h, "POST", "/respond", killBody, "Bearer wrong"); rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong token should 401, got %d", rr.Code)
	}
	if rr := doReq(h, "POST", "/respond", killBody, "Bearer secret"); rr.Code != http.StatusOK {
		t.Errorf("valid auth should 200, got %d (%s)", rr.Code, rr.Body)
	}
}

func TestHTTPRespondFailsClosedWithoutToken(t *testing.T) {
	h := newTestHandler(t, "", true, &FakeExecutor{})
	if rr := doReq(h, "POST", "/respond", killBody, "Bearer x"); rr.Code != http.StatusServiceUnavailable {
		t.Errorf("no token should 503 (fail closed), got %d", rr.Code)
	}
}

func TestHTTPRespondMethodAndBody(t *testing.T) {
	h := newTestHandler(t, "secret", true, &FakeExecutor{})
	if rr := doReq(h, "GET", "/respond", "", "Bearer secret"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /respond should 405, got %d", rr.Code)
	}
	if rr := doReq(h, "POST", "/respond", "{not json", "Bearer secret"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad json should 400, got %d", rr.Code)
	}
	if rr := doReq(h, "POST", "/respond", `{"action":"kill"}`, "Bearer secret"); rr.Code != http.StatusBadRequest {
		t.Errorf("missing target should 400, got %d", rr.Code)
	}
}

func TestHTTPRespondDryRunReturnsResultNoExecute(t *testing.T) {
	fake := &FakeExecutor{}
	h := newTestHandler(t, "secret", true, fake) // dry-run
	rr := doReq(h, "POST", "/respond", killBody, "Bearer secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var res Result
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || !res.OK || res.Action != "kill" {
		t.Errorf("result=%+v", res)
	}
	if fake.CallCount() != 0 {
		t.Errorf("dry-run handler must not execute, got %d calls", fake.CallCount())
	}
}

func TestHTTPRespondLiveExecutes(t *testing.T) {
	fake := &FakeExecutor{}
	h := newTestHandler(t, "secret", false, fake) // live
	rr := doReq(h, "POST", "/respond", killBody, "Bearer secret")
	var res Result
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res.DryRun {
		t.Error("live handler result should not be dry-run")
	}
	if fake.CallCount() != 1 {
		t.Errorf("live handler should execute once, got %d", fake.CallCount())
	}
}

func TestHTTPRespondGuardRefusalIsOKStatusWithFailResult(t *testing.T) {
	// A guardrail refusal is a valid response (200) carrying OK=false, not an
	// HTTP error — the operator sees exactly why it was refused.
	fake := &FakeExecutor{}
	h := newTestHandler(t, "secret", false, fake)
	body := `{"action":"kill","target":"1"}`
	rr := doReq(h, "POST", "/respond", body, "Bearer secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("refusal should still be 200, got %d", rr.Code)
	}
	var res Result
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res.OK || !strings.Contains(res.Detail, "refused") {
		t.Errorf("expected refused result, got %+v", res)
	}
	if fake.CallCount() != 0 {
		t.Errorf("refused request must not execute")
	}
}

func TestHTTPRespondBodyBounded(t *testing.T) {
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true, testGuards(), fixedClock())
	h := NewHandler(r, "secret", 8) // 8-byte cap
	rr := doReq(h, "POST", "/respond", killBody, "Bearer secret")
	if rr.Code == http.StatusOK {
		t.Errorf("oversized body should be rejected, got %d", rr.Code)
	}
}
