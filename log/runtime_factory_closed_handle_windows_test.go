package log

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Windows File.Stat returns the native invalid-handle error after Close.
func runtimeLogFileStatIsClosed(err error) bool {
	return errors.Is(err, os.ErrClosed) || errors.Is(err, windows.ERROR_INVALID_HANDLE)
}
