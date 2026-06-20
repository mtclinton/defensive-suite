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
	"syscall"
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
	mu      sync.Mutex
	items   []report.Finding
	max     int
	dropped int // findings trimmed by the cap since the last Drain
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
		b.dropped += len(b.items) - b.max
		b.items = append([]report.Finding(nil), b.items[len(b.items)-b.max:]...)
	}
}

// Snapshot returns a copy of the current findings.
func (b *Buffer) Snapshot() []report.Finding {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]report.Finding(nil), b.items...)
}

// Drain returns a copy of the pending findings and clears the buffer. `run` mode
// posts these as an Append delta each flush, so the collector accumulates the
// event stream rather than losing findings the bounded buffer would later trim.
func (b *Buffer) Drain() []report.Finding {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := append([]report.Finding(nil), b.items...)
	b.items = nil
	b.dropped = 0
	return out
}

// Dropped reports how many findings were discarded because the cap was hit since
// the buffer was last drained — a non-zero value means the flush window saw more
// findings than BufferMax and some were trimmed before they could be posted.
func (b *Buffer) Dropped() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

// Len reports the current finding count.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

// maxReadPerPoll bounds how many bytes Tail consumes per poll: an unbounded
// io.ReadAll on a file an attacker can grow fast would let a single poll balloon
// the agent's memory (the unit's MemoryMax=128M would then OOM-kill it). The
// remaining bytes are picked up on the next tick.
const maxReadPerPoll = 8 * 1024 * 1024

// maxLeftover caps the retained partial-line buffer. An unterminated or huge
// line (no '\n') would otherwise grow leftover without bound across polls. When
// the cap is exceeded we drop the partial line and resync at the next newline,
// mirroring ParseStream's per-line cap.
const maxLeftover = 8 * 1024 * 1024

// fileIno returns the inode of an os.FileInfo (linux + darwin), or 0 if
// unavailable, used to detect a rename+recreate rotation a size check misses.
func fileIno(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

// Tail follows a growing file, calling fn for each complete line. It starts at
// the current end (only new events), retains partial lines across reads (bounded
// by maxLeftover), reads at most maxReadPerPoll bytes per tick, and handles
// rotation — both a size shrink (truncate) AND a rename+recreate detected via an
// inode change (which a size-only check misses when the new file already grew
// past the old offset). A not-yet-present file is waited for. Returns when ctx
// is done.
func Tail(ctx context.Context, path string, poll time.Duration, fn func(string)) error {
	var offset int64
	var ino uint64
	var leftover []byte
	if st, err := os.Stat(path); err == nil {
		offset = st.Size()
		ino = fileIno(st)
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
			curIno := fileIno(st)
			rotated := st.Size() < offset || (curIno != 0 && ino != 0 && curIno != ino)
			if rotated {
				offset, leftover = 0, nil // truncated, or rename+recreate
			}
			ino = curIno
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
			data, _ := io.ReadAll(io.LimitReader(f, maxReadPerPoll))
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
			// Cap the retained partial line: an unterminated/huge line would grow
			// leftover unbounded. Drop it and resync at the next newline.
			if len(buf) > maxLeftover {
				buf = nil
			}
			leftover = append([]byte(nil), buf...)
		}
	}
}
