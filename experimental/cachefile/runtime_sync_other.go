//go:build !windows

package cachefile

import (
	"errors"
	"os"
	"path/filepath"
)

// The caller has already synced and closed the exclusively created file.
func syncRuntimeFileCreation(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
