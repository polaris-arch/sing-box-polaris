//go:build !linux && !darwin && !windows

package daemon

import (
 "errors"
 "os"
)

func prepareRuntimeFileMetadata(_ string, _ *os.File, _ os.FileInfo) error {
 return errors.New("runtime persistence ownership preservation is unavailable on this platform")
}
func replaceRuntimeOwnedFile(_, _ string) (bool, error) {
 return false, errors.New("runtime persistence replacement is unavailable on this platform")
}
