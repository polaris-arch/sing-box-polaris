//go:build darwin || linux || windows

package libbox

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Unlike the historical diagnostic snapshot writer, this callback must return
// every durability failure to the already-committed operation. A rename may
// have succeeded even when the following directory sync fails; callers must
// keep COMMITTED_DURABILITY_PENDING, never pretend the runtime was rolled back.
func saveRuntimeConfigSnapshot(content []byte) error {
	return writeRuntimeConfigSnapshot(configSnapshotPath(), content, func(file *os.File) error {
		if runtime.GOOS != "android" && runtime.GOOS != "windows" {
			return file.Chown(sUserID, sGroupID)
		}
		return nil
	})
}

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
