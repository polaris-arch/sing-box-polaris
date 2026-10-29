//go:build unix

package originca

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"golang.org/x/sys/unix"
)

func TestRuntimeRootStorageFIFOReplacementJoinsLeaseWorkerAndUnlock(t *testing.T) {
	if mode := os.Getenv("POLARIS_TEST_ORIGIN_FIFO_MODE"); mode != "" {
		dir := os.Getenv("POLARIS_TEST_ORIGIN_FIFO_DIR")
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		storage := &originRootStorage{root: root}
		if err = storage.Lock(t.Context(), "issuer"); err != nil {
			t.Fatal(err)
		}
		storage.mu.Lock()
		lock := storage.locks["locks/issuer.lock"]
		storage.mu.Unlock()
		if err = root.Rename("locks/issuer.lock", "locks/held.lock"); err != nil {
			t.Fatal(err)
		}
		if err = unix.Mkfifo(filepath.Join(dir, "locks", "issuer.lock"), 0o600); err != nil {
			t.Fatal(err)
		}
		if mode == "heartbeat" {
			// Exercise the real five-second worker, not a fake immediate probe.
			select {
			case <-lock.done:
			case <-time.After(7 * time.Second):
				t.Fatal("FIFO replacement blocked the actual lease maintenance worker")
			}
		}
		if err = storage.Unlock(t.Context(), "issuer"); err == nil {
			t.Fatal("FIFO replacement was accepted as the original lease")
		}
		select {
		case <-lock.done:
		default:
			t.Fatal("Unlock returned without joining the actual lease worker")
		}
		if _, err = lock.file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("failed lease identity cleanup leaked the original file handle")
		}
		if storage.Close() == nil {
			t.Fatal("changed lease identity lost UnknownCleanup")
		}
		if _, err = root.Stat("."); err != nil {
			t.Fatal("UnknownCleanup released the directory capability early", err)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"unlock", "heartbeat"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			// The child owns every production worker. Deadline kills and Wait
			// joins that process, so a blocked old implementation cannot leak one.
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRuntimeRootStorageFIFOReplacementJoinsLeaseWorkerAndUnlock$")
			cmd.Env = append(os.Environ(), "POLARIS_TEST_ORIGIN_FIFO_MODE="+mode, "POLARIS_TEST_ORIGIN_FIFO_DIR="+dir)
			cmd.WaitDelay = time.Second
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("FIFO lease cleanup did not reject and join within its deadline: %v; context=%v; output=%s", err, ctx.Err(), output)
			}
		})
	}
}

func TestRuntimeStorageRootAcquisitionPreservesDirectoryAliasSemantics(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "absolute")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(dir, "relative")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	want, err := os.Stat("target")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"target", "target/", "target/.", "absolute", "relative", target, "target/../target"} {
		root, openErr := originOpenStorageRoot(name)
		if openErr != nil {
			t.Fatal(name, openErr)
		}
		actual, statErr := root.Stat(".")
		if closeErr := root.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if statErr != nil || !os.SameFile(want, actual) {
			t.Fatal("actual acquired directory changed", name, statErr)
		}
	}
	for _, name := range []string{".", "/"} {
		root, openErr := originOpenStorageRoot(name)
		if openErr != nil {
			t.Fatal("root/dot boundary", name, openErr)
		}
		if err = root.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if root, openErr := originOpenStorageRoot(""); openErr == nil || root != nil {
		t.Fatal("empty pathname acquired current directory", openErr)
	}
	if root, openErr := originOpenStorageRoot(strings.Repeat("x", 4096)); openErr == nil || root != nil || !errors.Is(openErr, unix.ENAMETOOLONG) {
		t.Fatal("overlong raw directory suffix did not fail closed", openErr)
	}
}

type originLockActionFixture struct {
	certmagic.Storage
	afterLock func()
}

func (f *originLockActionFixture) Lock(ctx context.Context, key string) error {
	if err := f.Storage.Lock(ctx, key); err != nil {
		return err
	}
	f.afterLock()
	return nil
}

// The first Err check belongs to List before metadata. The second belongs to
// readDirectory immediately before its actual flagged open, after Stat succeeds.
type originListOpenBoundary struct {
	context.Context
	checks     int
	beforeOpen func()
}

func (c *originListOpenBoundary) Err() error {
	c.checks++
	if c.checks == 2 {
		c.beforeOpen()
	}
	return c.Context.Err()
}

type originLeasePollBoundary struct {
	context.Context
	polls        int
	afterSeventh func()
}

func (c *originLeasePollBoundary) Done() <-chan struct{} {
	c.polls++
	if c.polls == 7 {
		c.afterSeventh()
	}
	return c.Context.Done()
}

func TestRuntimeRootStorageUnsafeIORejectsFIFOWithFiniteOwner(t *testing.T) {
	if mode := os.Getenv("POLARIS_TEST_ORIGIN_IO_MODE"); mode != "" {
		dir := os.Getenv("POLARIS_TEST_ORIGIN_IO_DIR")
		root, err := originOpenStorageRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		storage := &originRootStorage{root: root}
		fifo := filepath.Join(dir, "fifo")
		if err = unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		switch mode {
		case "root", "root-alias", "root-replaced":
			name := fifo
			if mode == "root-alias" {
				name = filepath.Join(dir, "alias")
				if err = os.Symlink(fifo, name); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "root-replaced" {
				name = filepath.Join(dir, "candidate")
				if err = os.Mkdir(name, 0o700); err != nil {
					t.Fatal(err)
				}
				if _, err = os.Stat(name); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(name, name+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err = unix.Mkfifo(name, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			acquired, openErr := originOpenStorageRoot(name)
			if acquired != nil {
				_ = acquired.Close()
			}
			if openErr == nil || !errors.Is(openErr, unix.ENOTDIR) {
				t.Fatal("actual Root acquisition did not reject FIFO as non-directory", openErr)
			}
			return
		case "cache-key", "cache-cert", "cache-meta", "held-cache-key", "held-cache-cert", "held-cache-meta":
			resource := certmagic.CertificateResource{SANs: []string{"example.invalid"}}
			keys := originStorageKeys(resource)
			for _, key := range keys {
				if err = root.MkdirAll(path.Dir(key), 0o700); err != nil {
					t.Fatal(err)
				}
				if err = storage.Store(t.Context(), key, []byte("ordinary invalid cache")); err != nil {
					t.Fatal(err)
				}
			}
			index := 0
			if strings.HasSuffix(mode, "cert") {
				index = 1
			}
			if strings.HasSuffix(mode, "meta") {
				index = 2
			}
			var held *originRootLock
			swap := func() {
				if err := root.Rename(keys[index], keys[index]+".held"); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(filepath.Join(dir, filepath.FromSlash(keys[index])), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			transport := new(originRequestCountFixture)
			s := originServiceWithStorageFixture(storage, transport)
			if strings.HasPrefix(mode, "held-") {
				s.storage = &originLockActionFixture{Storage: storage, afterLock: func() {
					storage.mu.Lock()
					held = storage.locks["locks/issuer.lock"]
					storage.mu.Unlock()
					swap()
				}}
			} else {
				swap()
			}
			err = s.initializeCertificate(t.Context())
			if transport.calls.Load() != 0 || s.runtime.closeErr == nil {
				t.Fatal("real unsafe cache continued HTTP/lost cleanup", transport.calls.Load(), s.runtime.closeErr)
			}
			if held != nil {
				select {
				case <-held.done:
				default:
					t.Fatal("held-cache failure did not join actual lease worker")
				}
				if _, statErr := held.file.Stat(); !errors.Is(statErr, os.ErrClosed) {
					t.Fatal("held-cache failure leaked actual lease FD", statErr)
				}
			}
		case "socket":
			// Only this already isolated child changes cwd. A short filesystem
			// address fits Linux and BSD/Darwin regardless of GOTMPDIR length;
			// all IO still uses the same retained Root acquired above.
			previous, cwdErr := os.Getwd()
			if cwdErr != nil {
				t.Fatal(cwdErr)
			}
			if cwdErr = os.Chdir(dir); cwdErr != nil {
				t.Fatal(cwdErr)
			}
			defer func() {
				if restoreErr := os.Chdir(previous); restoreErr != nil {
					t.Error("restore child cwd", restoreErr)
				}
			}()
			listener, listenErr := net.ListenUnix("unix", &net.UnixAddr{Name: "socket", Net: "unix"})
			if listenErr != nil {
				t.Fatal(listenErr)
			}
			defer func() {
				// This runs before cwd restoration, so the relative socket name
				// is closed and unlinked within its actual owned directory.
				if closeErr := listener.Close(); closeErr != nil {
					t.Error("close actual socket listener", closeErr)
				}
				if _, statErr := root.Lstat("socket"); !errors.Is(statErr, os.ErrNotExist) {
					t.Error("listener did not retire socket name", statErr)
				}
			}()
			info, statErr := root.Lstat("socket")
			if statErr != nil || info.Mode()&os.ModeSocket == 0 {
				t.Fatal("fixture is not a real filesystem socket in the retained root", statErr)
			}
			_, err = storage.Load(t.Context(), "socket")
		case "load", "load-alias", "list-prefix":
			key := "fifo"
			if mode == "load-alias" {
				key = "alias"
				if err = os.Symlink("fifo", filepath.Join(dir, key)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "list-prefix" {
				_, err = storage.List(t.Context(), key, true)
			} else {
				_, err = storage.Load(t.Context(), key)
			}
		case "empty-then-fifo":
			if err = root.Mkdir("locks", 0o700); err != nil {
				t.Fatal(err)
			}
			if err = root.WriteFile("locks/issuer.lock", nil, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			boundary := &originLeasePollBoundary{Context: ctx, afterSeventh: func() {
				if err := root.Rename("locks/issuer.lock", "locks/empty-held"); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(filepath.Join(dir, "locks", "issuer.lock"), 0o600); err != nil {
					t.Fatal(err)
				}
			}}
			err = storage.Lock(boundary, "issuer")
			info, statErr := root.Lstat("locks/issuer.lock")
			if boundary.polls != 7 || statErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
				t.Fatal("empty history deleted unsafe replacement", boundary.polls, statErr)
			}
		case "lock":
			if err = root.Mkdir("locks", 0o700); err != nil {
				t.Fatal(err)
			}
			if err = unix.Mkfifo(filepath.Join(dir, "locks", "issuer.lock"), 0o600); err != nil {
				t.Fatal(err)
			}
			err = storage.Lock(t.Context(), "issuer")
			info, statErr := root.Lstat("locks/issuer.lock")
			if statErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
				t.Fatal("existing FIFO lease was stolen/deleted", statErr)
			}
			if len(storage.locks) != 0 {
				t.Fatal("FIFO conflict created a lease worker")
			}
		case "list-start-replaced", "list-alias-replaced":
			if err = root.Mkdir("walk", 0o700); err != nil {
				t.Fatal(err)
			}
			prefix := "walk"
			if mode == "list-alias-replaced" {
				prefix = "start-alias"
				if err = os.Symlink("walk", filepath.Join(dir, prefix)); err != nil {
					t.Fatal(err)
				}
			}
			boundary := &originListOpenBoundary{Context: t.Context(), beforeOpen: func() {
				if err := root.Rename("walk", "retained"); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(filepath.Join(dir, "walk"), 0o600); err != nil {
					t.Fatal(err)
				}
			}}
			_, err = storage.List(boundary, prefix, true)
			if boundary.checks != 2 {
				t.Fatal("did not reach post-metadata actual directory-open boundary", boundary.checks)
			}
			info, statErr := root.Lstat("walk")
			if statErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
				t.Fatal("unsafe prefix was removed or replaced", statErr)
			}
		case "list-replaced":
			if err = root.Mkdir("walk", 0o700); err != nil {
				t.Fatal(err)
			}
			readDirectory := func(ctx context.Context, name string) ([]os.DirEntry, error) {
				entries, readErr := storage.readDirectory(ctx, name)
				if name == "." && readErr == nil {
					// These real entries still classify walk as a directory.
					// Replace it before the real recursive directory opener.
					if err := root.Rename("walk", "retained"); err != nil {
						t.Fatal(err)
					}
					if err := unix.Mkfifo(filepath.Join(dir, "walk"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return entries, readErr
			}
			_, err = originListDirectory(t.Context(), ".", true, readDirectory)
		case "opened-replaced":
			if err = root.WriteFile("blob", []byte("held inode"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, openErr := root.OpenFile("blob", originStorageReadFlags, 0)
			if openErr != nil {
				t.Fatal(openErr)
			}
			if err = root.Rename("blob", "held-blob"); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err = unix.Mkfifo(filepath.Join(dir, "blob"), 0o600); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			data, readErr := originReadOpenedFile(t.Context(), file, 32)
			if readErr != nil || string(data) != "held inode" {
				t.Fatal("reader followed replacement instead of actual FD", readErr)
			}
			if _, err = file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("real retained read FD leaked", err)
			}
			return
		default:
			t.Fatal("unknown child mode", mode)
		}
		if !originStorageIsUnsafe(err) || storage.Close() == nil {
			t.Fatal("FIFO storage uncertainty was not retained", mode, err)
		}
		if _, err = root.Stat("."); err != nil {
			t.Fatal("unsafe root released before confirmed cleanup", err)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"root", "root-alias", "root-replaced", "socket", "load", "load-alias", "empty-then-fifo", "lock", "list-prefix", "list-start-replaced", "list-alias-replaced", "list-replaced", "opened-replaced", "cache-key", "cache-cert", "cache-meta", "held-cache-key", "held-cache-cert", "held-cache-meta"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRuntimeRootStorageUnsafeIORejectsFIFOWithFiniteOwner$")
			cmd.Env = append(os.Environ(), "POLARIS_TEST_ORIGIN_IO_MODE="+mode, "POLARIS_TEST_ORIGIN_IO_DIR="+t.TempDir())
			cmd.WaitDelay = time.Second
			output, runErr := cmd.CombinedOutput()
			if runErr != nil {
				t.Fatalf("real child did not reject/join: %v context=%v output=%s", runErr, ctx.Err(), output)
			}
		})
	}
}
