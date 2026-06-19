//go:build linux

package honeytoken

import (
	"os"
	"syscall"
	"time"
)

// times extracts access and modify times from a FileInfo on Linux. atime is the
// load-bearing signal: a read of a decoy advances it, which is the trip. mtime
// catches a write/replace. Falls back to ModTime for both if the underlying
// syscall stat is unavailable.
func times(info os.FileInfo) (atime, mtime time.Time) {
	mtime = info.ModTime()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		atime = time.Unix(st.Atim.Sec, st.Atim.Nsec)
		mtime = time.Unix(st.Mtim.Sec, st.Mtim.Nsec)
		return atime, mtime
	}
	return mtime, mtime
}
