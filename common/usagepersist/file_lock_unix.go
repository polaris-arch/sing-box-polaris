//go:build !windows

package usagepersist

import (
	"errors"
	"os"
	"syscall"
)

func lockUsageFile(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return ErrFileInUse
	}
	return err
}
