//go:build darwin

package honeytoken

import (
	"os"
	"syscall"
	"time"
)

// times extracts access and modify times on darwin (BSD stat field names). This
// build exists so the test suite runs on the macOS dev box; the production target
// is Linux (times_linux.go).
func times(info os.FileInfo) (atime, mtime time.Time) {
	mtime = info.ModTime()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		atime = time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec)
		mtime = time.Unix(st.Mtimespec.Sec, st.Mtimespec.Nsec)
		return atime, mtime
	}
	return mtime, mtime
}
