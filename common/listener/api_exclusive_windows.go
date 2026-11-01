//go:build windows

package listener

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// Go's ordinary TCP listener avoids SO_REUSEADDR but does not request Windows
// exclusive address ownership. A local control plane must prevent a later
// SO_REUSEADDR socket from taking over its tuple while custody is retained.
func apiExclusiveControl(_, _ string, raw syscall.RawConn) error {
	// Winsock SO_EXCLUSIVEADDRUSE is the bitwise complement of SO_REUSEADDR (4).
	var socketErr error
	err := raw.Control(func(fd uintptr) {
		socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, ^int(4), 1)
	})
	if err != nil {
		return err
	}
	return socketErr
}
