//go:build unix

package certificate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRuntimeStorageIdentityRejectsFIFOWithoutWriter(t *testing.T) {
	if mode := os.Getenv("POLARIS_TEST_IDENTITY_FIFO_MODE"); mode != "" {
		dir := os.Getenv("POLARIS_TEST_IDENTITY_FIFO_DIR")
		name := "fifo"
		if mode == "directory-alias" || mode == "root-alias" {
			name = "alias"
		}
		var info os.FileInfo
		var err error
		if mode == "directory" || mode == "directory-alias" || mode == "replacement" {
			info, err = RuntimeDirectoryIdentity(filepath.Join(dir, name))
		} else {
			root, openErr := os.OpenRoot(dir)
			if openErr != nil {
				t.Fatal(openErr)
			}
			info, err = RuntimeRootIdentity(root, name)
			err = errors.Join(err, root.Close())
		}
		if err == nil || info != nil {
			t.Fatal("metadata probe accepted a FIFO with no writer", info, err)
		}
		return
	}
	// NONBLOCK must be on the actual open, including after a name/type race;
	// a pre-open Lstat check alone cannot provide this property.
	if runtimeStorageOpenFlags&syscall.O_NONBLOCK == 0 || runtimeStorageDirectoryOpenFlags&syscall.O_NONBLOCK == 0 || runtimeStorageDirectoryOpenFlags&syscall.O_DIRECTORY == 0 {
		t.Fatal("metadata probe omitted the atomic nonblocking-open flag")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"directory", "root", "directory-alias", "root-alias", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			fifo := filepath.Join(dir, "fifo")
			if mode == "replacement" {
				if err := os.Mkdir(fifo, 0o700); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(fifo)
				if err != nil || !info.IsDir() {
					t.Fatal("replacement fixture was not initially a directory", err)
				}
				if err = os.Rename(fifo, filepath.Join(dir, "old")); err != nil {
					t.Fatal(err)
				}
			}
			if err := unix.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("fifo", filepath.Join(dir, "alias")); err != nil {
				t.Fatal(err)
			}
			// A subprocess gives even the blocking regression a finite lifetime;
			// timeout kills and Wait joins the actual probe, without a spare writer.
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRuntimeStorageIdentityRejectsFIFOWithoutWriter$")
			cmd.Env = append(os.Environ(), "POLARIS_TEST_IDENTITY_FIFO_MODE="+mode, "POLARIS_TEST_IDENTITY_FIFO_DIR="+dir)
			cmd.WaitDelay = time.Second
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("FIFO probe did not reject and join within its deadline: %v; context=%v; output=%s", err, ctx.Err(), output)
			}
		})
	}
}

func TestRuntimeStorageIdentitySnapshotsOpenedObjectBeforePathReplacement(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, rooted := range []bool{false, true} {
		t.Run(map[bool]string{false: "path", true: "root-relative"}[rooted], func(t *testing.T) {
			name := map[bool]string{false: "path-file", true: "root-file"}[rooted]
			full := filepath.Join(dir, name)
			if err := os.WriteFile(full, []byte("held object"), 0o600); err != nil {
				t.Fatal(err)
			}
			var file *os.File
			var err error
			if rooted {
				file, err = root.OpenFile(name, runtimeStorageOpenFlags, 0)
			} else {
				file, err = os.OpenFile(full, runtimeStorageOpenFlags, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err = os.Rename(full, full+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err = unix.Mkfifo(full, 0o600); err != nil {
				t.Fatal(err)
			}
			identity, err := runtimeStorageIdentity(file)
			if err != nil {
				t.Fatal("snapshot followed the replacement FIFO rather than its opened object", err)
			}
			actual, err := RuntimeRootIdentity(root, name+"-moved")
			if err != nil || !os.SameFile(identity, actual) {
				t.Fatal("opened-object identity changed with its pathname", err)
			}
			if _, err = file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("snapshot did not close its actual probe descriptor", err)
			}
		})
	}
}
