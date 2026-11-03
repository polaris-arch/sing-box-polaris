//go:build !windows

package originca

import (
	"errors"
	"os"
)

func runtimeRootFileStatIsClosed(err error) bool {
	return errors.Is(err, os.ErrClosed)
}
