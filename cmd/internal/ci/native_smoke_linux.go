package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func prepareNativeSmoke(_ context.Context, core string, row map[string]any, members map[string][]byte, execution *nativeSmokeExecution) error {
	variant := row["variant"].(map[string]any)
	if row["target"] != "linux/amd64" || !nativeFieldsMatch(variant, map[string]any{"linkage": "shared-purego", "legacy": false, "libc": ""}) {
		return nil
	}
	corePin := row["core"].(map[string]any)
	sidecar := row["sidecar"].(map[string]any)
	if sidecar["member"] != "libcronet.so" {
		return fmt.Errorf("sealed execution requires the selected Linux sidecar")
	}
	executable, err := sealNativeSmokeMember(members[corePin["member"].(string)], corePin["sha256"].(string), 0o500)
	if err != nil {
		return err
	}
	library, err := sealNativeSmokeMember(members[sidecar["member"].(string)], sidecar["sha256"].(string), 0o400)
	if err != nil {
		return errors.Join(err, executable.Close())
	}
	execution.close = func() error { return errors.Join(library.Close(), executable.Close()) }
	execution.command = func(ctx context.Context, args ...string) *exec.Cmd {
		// os/exec installs ExtraFiles at child FDs 3 and 4 before execve.
		command := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
		command.Dir = filepath.Dir(core)
		command.ExtraFiles = []*os.File{executable, library}
		command.Env = []string{"PATH=/bin:/usr/bin", "POLARIS_CRONET_LIBRARY_FD=4"}
		return command
	}
	execution.proofKey = "sealedExecution"
	execution.observe = func() (map[string]any, error) {
		coreSeals, err := unix.FcntlInt(executable.Fd(), unix.F_GET_SEALS, 0)
		if err != nil {
			return nil, err
		}
		sidecarSeals, err := unix.FcntlInt(library.Fd(), unix.F_GET_SEALS, 0)
		if err != nil {
			return nil, err
		}
		return map[string]any{"sidecar": sidecar, "coreSeals": coreSeals, "sidecarSeals": sidecarSeals}, nil
	}
	return nil
}

func sealNativeSmokeMember(data []byte, expected string, mode os.FileMode) (_ *os.File, err error) {
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if len(data) == 0 || len(data) > 96<<20 {
		return nil, fmt.Errorf("sealed native member exceeds budget")
	}
	fd, err := unix.MemfdCreate("polaris-native-smoke", unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "polaris-native-smoke")
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	if _, err := file.Write(data); err != nil {
		return nil, err
	}
	if err := file.Chmod(mode); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, err
	}
	actual, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return nil, err
	}
	if actual != seals {
		return nil, fmt.Errorf("native member seals differ")
	}
	digest := sha256.New()
	size, err := io.Copy(digest, io.NewSectionReader(file, 0, int64(len(data))+1))
	if err != nil {
		return nil, err
	}
	if size != int64(len(data)) || fmt.Sprintf("%x", digest.Sum(nil)) != expected {
		return nil, fmt.Errorf("sealed native bytes differ from final archive")
	}
	return file, nil
}
