//go:build darwin || linux || windows

package libbox

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// writeRuntimeConfigSnapshot returns every durability failure. A rename may
// have succeeded even when the following directory sync fails; a future restart
// source owner must retain COMMITTED_DURABILITY_PENDING in that case.
func writeRuntimeConfigSnapshot(path string, content []byte, prepare func(*os.File) error) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".runtime-config-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	closed, renamed := false, false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !renamed {
			_ = os.Remove(temporary)
		}
	}()
	// CreateTemp uses 0600. Never make the credential-bearing candidate public.
	if prepare != nil {
		if err := prepare(file); err != nil {
			return err
		}
	}
	n, err := file.Write(content)
	if err != nil {
		return err
	}
	if n != len(content) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	closed = true
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	renamed = true
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	// Targets that cannot certify directory sync remain explicitly pending.
	// This is not a portable claim of power-loss durability on all filesystems.
	return errors.Join(directory.Sync(), directory.Close())
}
