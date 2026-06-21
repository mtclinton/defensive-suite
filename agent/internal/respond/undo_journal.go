package respond

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// undo_journal.go provides the §4.6 append-only `auto-undo.jsonl` journal: the
// forensic record of every would-be-LIVE auto-action, carrying everything needed
// to reverse it. It is a structured TYPE + a unit-tested WRITER only. In THIS
// increment it is NEVER written by the run path — the bridge→Respond wire is a
// deliberate post-soak step (DEFERRED), and the bridge holds no responder/journal.
// The type and writer exist now so the future wire is a structured record, not a
// shelled string; a unit test round-trips the writer.

// UndoRecord is one append-only auto-undo journal entry (§4.6). It records, per
// would-be-live auto-action: the time, the forward Request, the resolved /proc
// target snapshot, the INVERSE Request (the structured reverse Action), and the
// triggering finding (its Check + key Related context, copied by value).
type UndoRecord struct {
	// Time is when the auto-action was decided/journaled.
	Time time.Time `json:"time"`
	// Request is the forward (destructive) action that would run.
	Request Request `json:"request"`
	// Snapshot is the resolved live-process identity the action was bound to
	// (§3.2): exe realpath, uid, starttime, exec_id, pid. This is the proof of WHAT
	// the action targeted, captured read-only at decision time.
	Snapshot UndoSnapshot `json:"snapshot"`
	// Inverse is the structured reverse Action that undoes Request — an
	// ActionUnquarantine/ActionDeIsolate/ActionRestoreKey Request, NEVER a shelled
	// free-text string. Empty Action means the forward action has no inverse (kill).
	Inverse Request `json:"inverse"`
	// Finding records the triggering finding's identity for triage: its Check,
	// Technique, the destination, and the human gate context.
	Finding UndoFinding `json:"finding"`
}

// UndoSnapshot is the resolved /proc target snapshot at decision time (read-only,
// never an actuator). It mirrors the identity the §4.2 fd-quarantine re-binds to.
type UndoSnapshot struct {
	Pid       int    `json:"pid"`
	Exe       string `json:"exe"`
	UID       int    `json:"uid"`
	StartTime uint64 `json:"start_time"`
	ExecID    string `json:"exec_id,omitempty"`
}

// UndoFinding is the triage context copied (by value) from the triggering
// finding. It deliberately does NOT embed report.Finding to keep respond free of
// an import cycle and to record only the attributes the journal needs.
type UndoFinding struct {
	Check     string   `json:"check"`
	Technique string   `json:"technique,omitempty"`
	Dst       string   `json:"dst,omitempty"`
	Related   []string `json:"related,omitempty"`
}

// UndoJournal is an append-only, JSON-lines auto-undo sink over an injected
// io.Writer (a file opened O_APPEND in production — a sibling of the audit log —
// or a bytes.Buffer in tests). Writes are serialized so concurrent appends cannot
// interleave a record. A nil journal or nil writer is a no-op (fail-safe), like
// AuditLog.
type UndoJournal struct {
	mu sync.Mutex
	w  io.Writer
}

// NewUndoJournal wraps w (one JSON object per line is appended to it).
func NewUndoJournal(w io.Writer) *UndoJournal {
	return &UndoJournal{w: w}
}

// Append writes one UndoRecord as a JSON line. A nil journal or nil writer is a
// no-op so a future caller works even before the sibling file is opened.
func (j *UndoJournal) Append(rec UndoRecord) error {
	if j == nil || j.w == nil {
		return nil
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	j.mu.Lock()
	defer j.mu.Unlock()
	_, err = j.w.Write(b)
	return err
}
