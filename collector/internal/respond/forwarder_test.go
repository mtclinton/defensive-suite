package respond

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortSocket returns a unix-socket path short enough to stay under the platform
// sun_path limit (~104 bytes on macOS). t.TempDir() embeds the (long) test name,
// which can overflow it, so we use a short MkdirTemp dir instead.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ds")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "a.sock")
}

// serveFakeAgentd stands up a unix-socket HTTP server that echoes a Result,
// standing in for agentd's /respond. It returns the socket path; the server is
// torn down via t.Cleanup.
func serveFakeAgentd(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	sock := shortSocket(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return sock
}

func TestSocketForwarderForwardsAndDecodes(t *testing.T) {
	var gotAuth string
	var gotReq Request
	sock := serveFakeAgentd(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Result{OK: true, Action: gotReq.Action, Target: gotReq.Target, DryRun: true, Detail: "ok"})
	})

	f := NewSocketForwarder(sock, "agent-tok")
	res, err := f.Forward(context.Background(), Request{Action: "kill", Target: "1234", Actor: "max"})
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if gotAuth != "Bearer agent-tok" {
		t.Errorf("forwarder did not send bearer, got %q", gotAuth)
	}
	if gotReq.Action != "kill" || gotReq.Target != "1234" {
		t.Errorf("agentd received wrong request: %+v", gotReq)
	}
	if !res.OK || !res.DryRun || res.Detail != "ok" {
		t.Errorf("decoded result=%+v", res)
	}
}

func TestSocketForwarderNon2xxIsError(t *testing.T) {
	sock := serveFakeAgentd(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	f := NewSocketForwarder(sock, "wrong")
	_, err := f.Forward(context.Background(), Request{Action: "kill", Target: "1"})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("non-2xx should error with status, got %v", err)
	}
}

func TestSocketForwarderUnreachable(t *testing.T) {
	f := NewSocketForwarder(shortSocket(t), "tok")
	_, err := f.Forward(context.Background(), Request{Action: "kill", Target: "1"})
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("missing socket should be unreachable error, got %v", err)
	}
}

func TestAuditLogNilSafe(t *testing.T) {
	var a *AuditLog
	if err := a.Write(AuditRecord{Action: "kill"}); err != nil {
		t.Errorf("nil audit log should no-op, got %v", err)
	}
	if err := NewAuditLog(nil).Write(AuditRecord{}); err != nil {
		t.Errorf("nil writer should no-op, got %v", err)
	}
}
