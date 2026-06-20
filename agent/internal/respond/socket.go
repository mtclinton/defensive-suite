package respond

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// Listen creates a unix-domain stream listener at path with 0600 permissions,
// removing any stale socket first. The caller serves an http.Handler on it. It
// is kept separate from the handler so the handler stays trivially testable with
// httptest (no socket needed).
func Listen(path string) (net.Listener, error) {
	// Remove a stale socket from a prior run; ignore "not found".
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("response socket: remove stale %q: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("response socket: listen %q: %w", path, err)
	}
	// 0600: root-only. The collector reaches it as the same user (root); the
	// unprivileged console never touches this socket directly.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("response socket: chmod %q: %w", path, err)
	}
	return ln, nil
}

// Serve runs an http.Server for h on ln until ctx is cancelled, then shuts it
// down gracefully and removes the socket file. addr is only used for the socket
// path cleanup.
func Serve(ctx context.Context, ln net.Listener, h http.Handler, socketPath string) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if err == http.ErrServerClosed {
			err = nil
		}
		errc <- err
	}()

	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		if socketPath != "" {
			_ = os.Remove(socketPath)
		}
		return nil
	case err := <-errc:
		if socketPath != "" {
			_ = os.Remove(socketPath)
		}
		return err
	}
}
