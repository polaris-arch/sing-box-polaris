//go:build !windows

package libbox

import "syscall"

func closeDup(fd int) error { return syscall.Close(fd) }

func dup(fd int) (nfd int, err error) {
	return syscall.Dup(fd)
}
