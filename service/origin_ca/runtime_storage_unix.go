//go:build unix

package originca

import (
	"os"
	"strings"
	"syscall"
)

const (
	originStorageReadFlags      = os.O_RDONLY | syscall.O_NONBLOCK
	originStorageDirectoryFlags = originStorageReadFlags | syscall.O_DIRECTORY
)

func originOpenStorageRoot(name string) (*os.Root, error) {
	if name == "" {
		return nil, &os.PathError{Op: "openroot", Path: name, Err: os.ErrInvalid}
	}
	// OpenRoot has no flags/FD constructor. Make the selected target a path
	// component that must be a directory, before opening its dot entry. Keep
	// this suffix raw: Join/Clean would remove the protection. Terminal aliases
	// (including absolute aliases) still resolve as they do in os.OpenRoot.
	if strings.HasSuffix(name, "/") {
		return os.OpenRoot(name + ".")
	}
	return os.OpenRoot(name + "/.")
}
