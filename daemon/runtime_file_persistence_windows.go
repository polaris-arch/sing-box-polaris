package daemon

import (
 "errors"
 "os"

 "github.com/sagernet/tailscale/atomicfile"
 "golang.org/x/sys/windows"
)

func prepareRuntimeFileMetadata(_ string, _ *os.File, _ os.FileInfo) error {
 // Match the existing boxdd atomicfile policy: ReplaceFileW preserves the
 // destination attributes and ACL. chmod on the temporary file is not an ACL.
 return nil
}
func replaceRuntimeOwnedFile(source, destination string) (bool, error) {
 return replaceAndFlushRuntimeFile(source, destination, atomicfile.Rename, flushRuntimeCommittedFile)
}
func flushRuntimeCommittedFile(path string) error {
 name, err := windows.UTF16PtrFromString(path)
 if err != nil { return err }
 handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
  windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
  windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH, 0)
 if err != nil { return err }
 // A failed flush or close remains pending although replacement has happened.
 // This is the existing Windows host policy, not a universal filesystem claim.
 return errors.Join(windows.FlushFileBuffers(handle), windows.CloseHandle(handle))
}
