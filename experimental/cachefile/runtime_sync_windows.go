package cachefile

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Windows cannot fsync a read-only directory handle. Use the existing Windows
// host committed-file policy: checked write-through file flush and handle close.
// Creation remains O_EXCL at the caller; no rename, replacement, or ACL change is
// performed here. Subsequent bbolt transactions retain their synchronous mode.
// This certifies the OS/filesystem's reported contract, not POSIX directory-fsync
// semantics or hardware guarantees beyond that contract.
func syncRuntimeFileCreation(path string) error {
	return syncRuntimeWindowsCreation(path, openRuntimeSyncFile, windows.FlushFileBuffers, windows.CloseHandle)
}

func openRuntimeSyncFile(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH, 0)
}

func syncRuntimeWindowsCreation(path string, open func(string) (windows.Handle, error), flush func(windows.Handle) error, closeHandle func(windows.Handle) error) error {
	handle, err := open(path)
	if err != nil {
		return err
	}
	return errors.Join(flush(handle), closeHandle(handle))
}
