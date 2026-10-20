//go:build linux || darwin

package daemon

import (
 "errors"
 "os"
 "path/filepath"
 "syscall"
)

func prepareRuntimeFileMetadata(path string, file *os.File, info os.FileInfo) error {
 original, ok := info.Sys().(*syscall.Stat_t)
 if !ok { return errors.New("runtime persistence source ownership unavailable") }
 temporary, err := file.Stat()
 if err != nil { return err }
 owner, ok := temporary.Sys().(*syscall.Stat_t)
 if !ok { return errors.New("runtime persistence temporary ownership unavailable") }
 // Privileged helper launches must not replace App-owned JSON with root-owned
 // JSON. Chown before chmod because chown can clear mode bits.
 if owner.Uid != original.Uid || owner.Gid != original.Gid {
  if err = file.Chown(int(original.Uid), int(original.Gid)); err != nil { return err }
 }
 if err = file.Chmod(info.Mode()); err != nil { return err }
 return checkRuntimeAccessMetadata(path, file.Name())
}
func replaceRuntimeOwnedFile(source, destination string) (bool, error) {
 return replaceAndFlushRuntimeFile(source, destination, os.Rename, func(path string) error {
  directory, err := os.Open(filepath.Dir(path))
  if err != nil { return err }
  return errors.Join(directory.Sync(), directory.Close())
 })
}
