package respond

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestListenCreates0600Socket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agentd.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket perm=%o want 0600", perm)
	}
	// A second Listen on the same path must succeed (stale socket removed).
	ln.Close()
	ln2, err := Listen(sock)
	if err != nil {
		t.Fatalf("relisten over stale socket: %v", err)
	}
	ln2.Close()
}

func TestServeOverUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agentd.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	fake := &FakeExecutor{}
	r := NewResponder(fake, NewAuditLog(&bytes.Buffer{}), true, testGuards(), fixedClock())
	h := NewHandler(r, "secret", 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, h, sock) }()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 3 * time.Second,
	}
	resp, err := client.Get("http://unix/healthz")
	if err != nil {
		t.Fatalf("healthz over socket: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Errorf("healthz=%d %q", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Serve did not shut down")
	}
	if _, err := os.Stat(sock); err == nil {
		t.Error("socket file should be removed on shutdown")
	}
}
