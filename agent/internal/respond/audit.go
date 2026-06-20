package respond

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// AuditRecord is one append-only audit line: the request, who/why, whether it
// was a dry-run, and the outcome. Stage distinguishes the two writes per request
// ("intent" before execution, "result" after) so a crash between them is visible
// in the log.
type AuditRecord struct {
	Time   time.Time `json:"time"`
	Stage  string    `json:"stage"` // "intent" or "result"
	Action string    `json:"action"`
	Target string    `json:"target"`
	Reason string    `json:"reason,omitempty"`
	Actor  string    `json:"actor,omitempty"`
	DryRun bool      `json:"dry_run"`
	OK     bool      `json:"ok"`
	Detail string    `json:"detail,omitempty"`
}

// AuditLog is an append-only, JSON-lines audit sink over an injected io.Writer
// (a file opened O_APPEND in production, a bytes.Buffer in tests). Writes are
// serialized so concurrent Respond calls cannot interleave a record.
type AuditLog struct {
	mu sync.Mutex
	w  io.Writer
}

// NewAuditLog wraps w (one JSON object per line is appended to it).
func NewAuditLog(w io.Writer) *AuditLog {
	return &AuditLog{w: w}
}

// write appends one record as a JSON line. A nil log or nil writer is a no-op so
// the Responder works even when no audit sink is configured (it shouldn't be,
// but failing safe beats panicking on the response path).
func (a *AuditLog) write(rec AuditRecord) error {
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

// Intent records the request before any execution.
func (a *AuditLog) Intent(now time.Time, req Request, dryRun bool) error {
	return a.write(AuditRecord{
		Time:   now,
		Stage:  "intent",
		Action: req.Action,
		Target: req.Target,
		Reason: req.Reason,
		Actor:  req.Actor,
		DryRun: dryRun,
	})
}

// Result records the outcome after execution (or the planned dry-run outcome).
func (a *AuditLog) Result(now time.Time, req Request, res Result) error {
	return a.write(AuditRecord{
		Time:   now,
		Stage:  "result",
		Action: req.Action,
		Target: req.Target,
		Reason: req.Reason,
		Actor:  req.Actor,
		DryRun: res.DryRun,
		OK:     res.OK,
		Detail: res.Detail,
	})
}
