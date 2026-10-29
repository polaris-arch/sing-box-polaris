//go:build unix

package certificate

import (
	"os"
	"syscall"
)

// Apply NONBLOCK at the actual open boundary. A pathname (including a rooted
// symlink target) can become a FIFO after any earlier metadata/type check.
// We only fstat and close this descriptor; no readiness wait or read follows.
const (
	runtimeStorageOpenFlags          = os.O_RDONLY | syscall.O_NONBLOCK
	runtimeStorageDirectoryOpenFlags = runtimeStorageOpenFlags | syscall.O_DIRECTORY
)
