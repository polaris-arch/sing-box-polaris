package originca

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func runtimeRootRenameIsSharingViolation(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

func TestRuntimeRootRenameSharingViolationClassification(t *testing.T) {
	for _, err := range []error{nil, os.ErrPermission, windows.ERROR_ACCESS_DENIED, windows.ERROR_INVALID_PARAMETER, errors.New("unrelated rename failure")} {
		if runtimeRootRenameIsSharingViolation(err) {
			t.Fatal("unrelated error satisfied the held-root sharing contract", err)
		}
	}
	wrapped := &os.LinkError{Op: "rename", Old: "old", New: "new", Err: windows.ERROR_SHARING_VIOLATION}
	if !runtimeRootRenameIsSharingViolation(wrapped) {
		t.Fatal("wrapped native sharing violation was not recognized")
	}
}

func TestRuntimeRootStorageWindowsPipeRejectedBeforeRead(t *testing.T) {
	if os.Getenv("POLARIS_TEST_ORIGIN_WINDOWS_PIPE") == "1" {
		var readHandle, writeHandle windows.Handle
		if err := windows.CreatePipe(&readHandle, &writeHandle, nil, 0); err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(writeHandle)
		file := os.NewFile(uintptr(readHandle), "private-pipe")
		if file == nil {
			_ = windows.CloseHandle(readHandle)
			t.Fatal("invalid owned pipe descriptor")
		}
		// The writer remains open with no data, so reading before the actual
		// handle's type check would block; the finite parent owns this process.
		value, err := originReadOpenedFile(t.Context(), file, originStorageLeaseLimit)
		if !originStorageIsUnsafe(err) || value != nil {
			t.Fatal("actual Windows pipe was read as a regular file", err)
		}
		if _, err = file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("rejected pipe handle leaked", err)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRuntimeRootStorageWindowsPipeRejectedBeforeRead$")
	cmd.Env = append(os.Environ(), "POLARIS_TEST_ORIGIN_WINDOWS_PIPE=1")
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native pipe rejection did not join: %v context=%v output=%s", err, ctx.Err(), output)
	}
}
