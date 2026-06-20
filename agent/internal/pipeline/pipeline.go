// Package pipeline ties parsing → rules → forwarding together: a one-shot
// ProcessReader (scan mode), a bounded rolling Buffer (the agent's current
// real-time posture), and a poll-based file Tailer for the Tetragon JSON export.
package pipeline

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/config"
	"github.com/mtclinton/defensive-suite/agent/internal/report"
	"github.com/mtclinton/defensive-suite/agent/internal/rules"
	"github.com/mtclinton/defensive-suite/agent/internal/tetragon"
)

func ruleCfg(cfg config.Config) rules.Config {
	return rules.Config{
		StagingDirs:    cfg.StagingDirs,
		SensitivePaths: cfg.SensitivePaths,
		BPFLoadFuncs:   cfg.BPFLoadFuncs,
		WriteFuncs:     cfg.WriteFuncs,
		BPFAllowlist:   cfg.BPFLoaderAllowlist,
	}
}

// EvalLine parses one Tetragon JSON line and returns the findings it triggers.
func EvalLine(line string, cfg config.Config) []report.Finding {
	e, ok := tetragon.ParseLine(line)
	if !ok {
		return nil
	}
	return rules.Eval(e, ruleCfg(cfg))
}

// ProcessReader evaluates an entire Tetragon JSON stream (scan / one-shot mode).
func ProcessReader(r io.Reader, cfg config.Config) []report.Finding {
	rc := ruleCfg(cfg)
	var out []report.Finding
	for _, e := range tetragon.ParseStream(r) {
		out = append(out, rules.Eval(e, rc)...)
	}
	return out
}

// Buffer is a bounded, concurrency-safe rolling set of findings.
type Buffer struct {
	mu    sync.Mutex
	items []report.Finding
	max   int
}

// NewBuffer makes a buffer capped at max findings (0 = unbounded).
func NewBuffer(max int) *Buffer { return &Buffer{max: max} }

// Add appends findings, trimming the oldest beyond the cap.
func (b *Buffer) Add(fs ...report.Finding) {
	if len(fs) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(b.items, fs...)
	if b.max > 0 && len(b.items) > b.max {
		b.items = append([]report.Finding(nil), b.items[len(b.items)-b.max:]...)
	}
}

// Snapshot returns a copy of the current findings.
func (b *Buffer) Snapshot() []report.Finding {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]report.Finding(nil), b.items...)
}

// Len reports the current finding count.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

// Tail follows a growing file, calling fn for each complete line. It starts at
// the current end (only new events), retains partial lines across reads, and
// handles truncation/rotation (size shrinks → restart from 0) and a
// not-yet-present file (waits). It returns when ctx is done.
func Tail(ctx context.Context, path string, poll time.Duration, fn func(string)) error {
	var offset int64
	var leftover []byte
	if st, err := os.Stat(path); err == nil {
		offset = st.Size()
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			st, err := os.Stat(path)
			if err != nil {
				continue // file gone / not yet present
			}
			if st.Size() < offset {
				offset, leftover = 0, nil // truncated or rotated
			}
			if st.Size() == offset {
				continue // no new data
			}
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}
			data, _ := io.ReadAll(f)
			f.Close()
			offset += int64(len(data))
			buf := append(leftover, data...)
			for {
				i := bytes.IndexByte(buf, '\n')
				if i < 0 {
					break
				}
				fn(string(buf[:i]))
				buf = buf[i+1:]
			}
			leftover = append([]byte(nil), buf...)
		}
	}
}
