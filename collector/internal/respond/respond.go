// Package respond is the collector's side of the manual-response path. The
// unprivileged collector never performs a privileged action itself: it
// authenticates the operator, forwards the Request to the root-owned agentd unix
// socket via a Forwarder, records both the request and the returned Result in an
// append-only audit log, and returns the Result. This keeps the console from
// ever talking to the root socket directly.
//
// The Request/Result shapes mirror agentd's wire contract (the collector is a
// distinct stdlib-only module, so the types are restated rather than imported).
package respond

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Request is the operator-issued response action forwarded to agentd.
type Request struct {
	Action string            `json:"action"`
	Target string            `json:"target"`
	Args   map[string]string `json:"args,omitempty"`
	Reason string            `json:"reason,omitempty"`
	Actor  string            `json:"actor,omitempty"`
}

// Result is agentd's outcome, returned to the caller verbatim.
type Result struct {
	OK     bool   `json:"ok"`
	Action string `json:"action"`
	Target string `json:"target"`
	DryRun bool   `json:"dry_run"`
	Detail string `json:"detail,omitempty"`
	Undo   string `json:"undo,omitempty"`
}

// AuditRecord is one append-only line in the collector-side audit log.
type AuditRecord struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Reason string    `json:"reason,omitempty"`
	Actor  string    `json:"actor,omitempty"`
	OK     bool      `json:"ok"`
	DryRun bool      `json:"dry_run"`
	Detail string    `json:"detail,omitempty"`
	Err    string    `json:"error,omitempty"`
}

// AuditLog is an append-only JSON-lines sink over an injected io.Writer.
type AuditLog struct {
	mu sync.Mutex
	w  io.Writer
}

// NewAuditLog wraps w.
func NewAuditLog(w io.Writer) *AuditLog {
	return &AuditLog{w: w}
}

// Write appends one record. A nil log/writer is a no-op.
func (a *AuditLog) Write(rec AuditRecord) error {
	if a == nil || a.w == nil {
		return nil
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.w.Write(b)
	return err
}
