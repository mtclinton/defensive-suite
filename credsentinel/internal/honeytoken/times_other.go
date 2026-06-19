//go:build !linux && !darwin

package honeytoken

import (
	"os"
	"time"
)

// times falls back to ModTime for both atime and mtime on platforms whose stat
// fields we do not special-case. The decoy mtime/content trips still work; only
// the atime read-trip is unavailable. The production target is Linux.
func times(info os.FileInfo) (atime, mtime time.Time) {
	mtime = info.ModTime()
	return mtime, mtime
}
