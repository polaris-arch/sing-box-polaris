//go:build !windows

package log

import (
	"errors"
	"os"
)

func runtimeLogFileStatIsClosed(err error) bool {
	return errors.Is(err, os.ErrClosed)
}
