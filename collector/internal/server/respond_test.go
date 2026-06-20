package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/mtclinton/defensive-suite/collector/internal/respond"
	"github.com/mtclinton/defensive-suite/collector/internal/store"
)

// fakeForwarder records the forwarded request and returns a canned Result/err.
type fakeForwarder struct {
	got   []respond.Request
	res   respond.Result
	err   error
	calls int
}

func (f *fakeForwarder) Forward(_ context.Context, req respond.Request) (respond.Result, error) {
	f.calls++
	f.got = append(f.got, req)
	return f.res, f.err
}

func newRespondServer(t *testing.T, token string, fwd respond.Forwarder, audit *bytes.Buffer) *Server {
	t.Helper()
	st, err := store.New(t.TempDir(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, "ingesttok", 1<<20, []byte("<title>dash</title>"))
	var al *respond.AuditLog
	if audit != nil {
		al = respond.NewAuditLog(audit)
	}
	return s.WithResponse(token, fwd, al)
}

const respondBody = `{"action":"kill","target":"1234","reason":"fileless","actor":"max"}`

func TestRespondAuth(t *testing.T) {
	fwd := &fakeForwarder{res: respond.Result{OK: true, Action: "kill", Target: "1234", DryRun: true}}
	s := newRespondServer(t, "resp-secret", fwd, nil)

	if rr := do(s, "POST", "/api/respond", respondBody, ""); rr.Code != http.StatusUnauthorized {
		t.Errorf("missing auth should 401, got %d", rr.Code)
	}
	if rr := do(s, "POST", "/api/respond", respondBody, "Bearer wrong"); rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong token should 401, got %d", rr.Code)
	}
	if fwd.calls != 0 {
		t.Errorf("unauthorized requests must not be forwarded, got %d", fwd.calls)
	}
	if rr := do(s, "POST", "/api/respond", respondBody, "Bearer resp-secret"); rr.Code != http.StatusOK {
		t.Errorf("valid auth should 200, got %d (%s)", rr.Code, rr.Body)
	}
}

func TestRespondDisabledWhenNotConfigured(t *testing.T) {
	// WithResponse not called → endpoint absent. A bare server 404s the path.
	st, _ := store.New(t.TempDir(), 0, 0)
	s := New(st, "ingesttok", 1<<20, []byte("x"))
	if rr := do(s, "POST", "/api/respond", respondBody, "Bearer x"); rr.Code != http.StatusNotFound {
		t.Errorf("unconfigured /api/respond should 404, got %d", rr.Code)
	}

	// Configured with an empty token → fails closed (503).
	fwd := &fakeForwarder{}
	s2 := newRespondServer(t, "", fwd, nil)
	if rr := do(s2, "POST", "/api/respond", respondBody, "Bearer x"); rr.Code != http.StatusServiceUnavailable {
		t.Errorf("empty-token response should 503, got %d", rr.Code)
	}
}

func TestRespondForwardsAndReturnsResult(t *testing.T) {
	want := respond.Result{OK: true, Action: "kill", Target: "1234", DryRun: true, Detail: "dry-run: would SIGKILL pid 1234"}
	fwd := &fakeForwarder{res: want}
	s := newRespondServer(t, "resp-secret", fwd, nil)

	rr := do(s, "POST", "/api/respond", respondBody, "Bearer resp-secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body)
	}
	if fwd.calls != 1 {
		t.Fatalf("expected one forward, got %d", fwd.calls)
	}
	if fwd.got[0].Action != "kill" || fwd.got[0].Target != "1234" || fwd.got[0].Actor != "max" {
		t.Errorf("forwarded request wrong: %+v", fwd.got[0])
	}
	var got respond.Result
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("returned result=%+v want %+v", got, want)
	}
}

func TestRespondAuditRecorded(t *testing.T) {
	var audit bytes.Buffer
	fwd := &fakeForwarder{res: respond.Result{OK: true, Action: "isolate", Target: "wlan0", DryRun: true, Detail: "would isolate"}}
	s := newRespondServer(t, "resp-secret", fwd, &audit)

	body := `{"action":"isolate","target":"wlan0","reason":"c2","actor":"max"}`
	if rr := do(s, "POST", "/api/respond", body, "Bearer resp-secret"); rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var rec respond.AuditRecord
	line := strings.TrimSpace(audit.String())
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("audit line %q: %v", line, err)
	}
	if rec.Action != "isolate" || rec.Target != "wlan0" || rec.Actor != "max" || rec.Reason != "c2" {
		t.Errorf("audit rec=%+v", rec)
	}
	if !rec.OK || !rec.DryRun || rec.Detail != "would isolate" {
		t.Errorf("audit outcome=%+v", rec)
	}
}

func TestRespondForwarderErrorIs502AndAudited(t *testing.T) {
	var audit bytes.Buffer
	fwd := &fakeForwarder{err: errors.New("agentd unreachable: dial unix")}
	s := newRespondServer(t, "resp-secret", fwd, &audit)

	rr := do(s, "POST", "/api/respond", respondBody, "Bearer resp-secret")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("forwarder error should 502, got %d", rr.Code)
	}
	// The failure is still audited (with the error recorded).
	var rec respond.AuditRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(audit.String())), &rec); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if rec.OK || rec.Err == "" {
		t.Errorf("error should be audited: %+v", rec)
	}
}

func TestRespondMethodAndBody(t *testing.T) {
	fwd := &fakeForwarder{res: respond.Result{OK: true}}
	s := newRespondServer(t, "resp-secret", fwd, nil)

	if rr := do(s, "GET", "/api/respond", "", "Bearer resp-secret"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET should 405, got %d", rr.Code)
	}
	if rr := do(s, "POST", "/api/respond", "{not json", "Bearer resp-secret"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad json should 400, got %d", rr.Code)
	}
	if rr := do(s, "POST", "/api/respond", `{"action":"kill"}`, "Bearer resp-secret"); rr.Code != http.StatusBadRequest {
		t.Errorf("missing target should 400, got %d", rr.Code)
	}
	if fwd.calls != 0 {
		t.Errorf("invalid requests must not forward, got %d", fwd.calls)
	}
}
