package respond

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Forwarder ships a validated Request to agentd and returns its Result. It is an
// interface so the real unix-socket client and a fake are swappable; every
// collector test uses the fake.
type Forwarder interface {
	Forward(ctx context.Context, req Request) (Result, error)
}

// SocketForwarder is the real Forwarder: an http.Client whose transport dials a
// unix-domain socket (agentd's /run/agentd.sock). The HTTP host in the URL is a
// placeholder; the DialContext ignores it and connects to SocketPath.
type SocketForwarder struct {
	SocketPath string
	Token      string
	client     *http.Client
}

// NewSocketForwarder builds a SocketForwarder dialing socketPath, presenting
// token as the bearer to agentd.
func NewSocketForwarder(socketPath, token string) *SocketForwarder {
	return &SocketForwarder{
		SocketPath: socketPath,
		Token:      token,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

// Forward POSTs req to http://agentd/respond over the unix socket and decodes
// the Result. A non-2xx from agentd becomes an error (the handler maps it to a
// 502 for the operator).
func (f *SocketForwarder) Forward(ctx context.Context, req Request) (Result, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Result{}, err
	}
	// The host is a fixed placeholder; the unix DialContext ignores it.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agentd/respond", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if f.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+f.Token)
	}
	resp, err := f.client.Do(httpReq)
	if err != nil {
		return Result{}, fmt.Errorf("agentd unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Result{}, fmt.Errorf("agentd returned status %d: %s", resp.StatusCode, bytes.TrimSpace(data))
	}
	var res Result
	if err := json.Unmarshal(data, &res); err != nil {
		return Result{}, fmt.Errorf("agentd returned undecodable result: %w", err)
	}
	return res, nil
}
