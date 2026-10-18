//go:build with_tailscale && (darwin || linux)

package tailscale

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func (t *Endpoint) prepareTaildropDirectory() (resultErr error) {
	relative, err := ownedTaildropRelative(t.server.Dir, t.taildrop.directory)
	if err != nil {
		return err
	}
	d := t.directory
	d.mu.Lock()
	lease := d.lease
	d.mu.Unlock()
	if lease == nil {
		return fmt.Errorf("tailscale: missing Taildrop directory lease")
	}
	if err := lease.checkAnchors(); err != nil {
		return err
	}
	fd, err := unix.Dup(lease.targetFD)
	if err != nil {
		return err
	}
	// Descriptor Close errors are sticky before the enclosing Start token ends.
	defer func() { err := unix.Close(fd); d.scope.Fail(err); resultErr = errors.Join(resultErr, err) }()
	for part := range strings.SplitSeq(relative, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("tailscale: invalid Taildrop child")
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) {
			mkdirErr := unix.Mkdirat(fd, part, 0o700)
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				return mkdirErr
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr == nil {
				if err := errors.Join(unix.Fsync(next), unix.Fsync(fd)); err != nil {
					d.scope.Fail(err)
					closeErr := unix.Close(next)
					d.scope.Fail(closeErr)
					return errors.Join(err, closeErr)
				}
			}
		}
		if openErr != nil {
			return openErr
		}
		closeErr := unix.Close(fd)
		fd = next
		if closeErr != nil {
			d.scope.Fail(closeErr)
			return closeErr
		}
	}
	return lease.checkAnchors()
}
