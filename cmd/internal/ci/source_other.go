//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func redirectedSource(info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}

func sourceProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateSourceProcess(command *exec.Cmd, force bool) error {
	signal := syscall.SIGTERM
	if force {
		signal = syscall.SIGKILL
	}
	err := syscall.Kill(-command.Process.Pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func sourceDiskFree(directory string) (uint64, error) {
	var status syscall.Statfs_t
	if err := syscall.Statfs(directory, &status); err != nil {
		return 0, err
	}
	return uint64(status.Bavail) * uint64(status.Bsize), nil
}
