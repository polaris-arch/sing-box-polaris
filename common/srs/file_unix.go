//go:build unix

package srs

import (
	"os"
	"syscall"
)

// A pathname or symlink target can become a FIFO before it is opened.
const readFileFlags = os.O_RDONLY | syscall.O_NONBLOCK
