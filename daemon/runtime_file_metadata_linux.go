package daemon

import (
 "bytes"
 "errors"

 "golang.org/x/sys/unix"
)

// Keep inherited access-control labels only when they exactly match. This does
// not copy arbitrary xattrs or expand the existing private JSON writer policy.
func checkRuntimeAccessMetadata(source, temporary string) error {
 for _, attribute := range []string{"system.posix_acl_access", "security.selinux", "security.SMACK64"} {
  original, err := runtimeAccessAttribute(source, attribute)
  if err != nil { return err }
  replacement, err := runtimeAccessAttribute(temporary, attribute)
  if err != nil { return err }
  if !bytes.Equal(original, replacement) { return errors.New("runtime persistence access-control metadata would change") }
 }
 return nil
}
func runtimeAccessAttribute(path, attribute string) ([]byte, error) {
 size, err := unix.Getxattr(path, attribute, nil)
 if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) { return nil, nil }
 if err != nil { return nil, err }
 value := make([]byte, size)
 count, err := unix.Getxattr(path, attribute, value)
 if err != nil { return nil, err }
 return value[:count], nil
}
