package originca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/certificate"

	"github.com/caddyserver/certmagic"
)

func TestRuntimeRootStorageRetainsActualDirectoryAcrossAliasChangeAndRename(t *testing.T) {
	base := t.TempDir()
	a, b, l := filepath.Join(base, "a"), filepath.Join(base, "b"), filepath.Join(base, "alias")
	for _, dir := range []string{a, b} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(a, l); err != nil {
		t.Fatal("private symlink fixture unavailable", err)
	}
	root, err := originOpenStorageRoot(l)
	if err != nil {
		t.Fatal(err)
	}
	storage := &originRootStorage{root: root}
	defer root.Close()
	identity, err := certificate.RuntimeRootIdentity(root, ".")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(l); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(b, l); err != nil {
		t.Fatal(err)
	}
	if err = storage.Lock(context.Background(), "issuer"); err != nil {
		t.Fatal(err)
	}
	if err = storage.Store(context.Background(), "certificates/fixture/cert", []byte("old epoch")); err != nil {
		t.Fatal(err)
	}
	legacy := &certmagic.FileStorage{Path: a}
	data, err := legacy.Load(context.Background(), "certificates/fixture/cert")
	if err != nil || string(data) != "old epoch" {
		t.Fatal("rooted cache lost FileStorage layout compatibility", err)
	}
	// The legacy locker must recognize this root owner's wire-compatible lease.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = legacy.Lock(ctx, "issuer")
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("legacy FileStorage ignored rooted lock", err)
	}
	storage.mu.Lock()
	lock := storage.locks["locks/issuer.lock"]
	storage.mu.Unlock()
	if err = storage.Unlock(context.Background(), "issuer"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-lock.done:
	default:
		t.Fatal("unlock did not join lock maintenance")
	}
	moved := filepath.Join(base, "moved")
	err = os.Rename(a, moved)
	if runtime.GOOS == "windows" {
		// os.Root deliberately omits FILE_SHARE_DELETE: retaining the directory
		// prevents rename on Windows, while Unix permits rename with rooted IO.
		if !runtimeRootRenameIsSharingViolation(err) {
			t.Fatal("held Windows root did not reject rename with a sharing violation", err)
		}
		if _, statErr := os.Stat(moved); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("rejected rename created a destination", statErr)
		}
		actual, statErr := certificate.RuntimeDirectoryIdentity(a)
		if statErr != nil || !os.SameFile(identity, actual) {
			t.Fatal("rejected rename lost original directory identity", statErr)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if err = storage.Store(context.Background(), "after-rename", []byte("same inode")); err != nil {
		t.Fatal(err)
	}
	if err = storage.Close(); err != nil {
		t.Fatal("confirmed storage release failed", err)
	}
	if runtime.GOOS == "windows" {
		if err = os.Rename(a, moved); err != nil {
			t.Fatal("released root capability still prevented rename", err)
		}
	}
	actual, err := certificate.RuntimeDirectoryIdentity(moved)
	if err != nil || !os.SameFile(identity, actual) {
		t.Fatal("root lost retained inode", err)
	}
	entries, err := os.ReadDir(b)
	if err != nil || len(entries) != 0 {
		t.Fatal("retained storage followed mutable original alias", err)
	}
	if _, err = os.Stat(filepath.Join(moved, "after-rename")); err != nil {
		t.Fatal("root IO did not follow original inode across rename", err)
	}
}

func TestRuntimeRootStorageObservesLegacyLeaseAndKeepsUnknownDirectoryHeld(t *testing.T) {
	dir := t.TempDir()
	root, err := originOpenStorageRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	storage := &originRootStorage{root: root}
	if err = root.Mkdir("locks", 0o700); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(originLockMeta{Created: time.Now(), Updated: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("locks/issuer.lock", metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = storage.Lock(ctx, "issuer")
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("rooted backend stole legacy lease", err)
	}
	storage.failed(errors.New("fixture cache cleanup unknown"))
	if storage.Close() == nil {
		t.Fatal("unconfirmed cache cleanup reported success")
	}
	if _, err = root.Stat("."); err != nil {
		t.Fatal("UnknownCleanup closed the held directory capability early", err)
	}
}

func TestRuntimeRootStorageCannotFollowChildSymlinkOutsideHeldDirectory(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Skip("private symlink fixture unavailable")
	}
	root, err := originOpenStorageRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	storage := &originRootStorage{root: root}
	if err = storage.Store(context.Background(), "escape/certificate", []byte("must stay owned")); err == nil {
		t.Fatal("cache IO escaped its held directory")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("unowned directory was written", err)
	}
}

// Wrappers still use a real descriptor for Stat/Read/Write/Close. They make
// growth and OS close-error boundaries deterministic without faking identity.
type originOpenedFileFixture struct {
	*os.File
	afterStat  func()
	statErr    error
	closeErr   error
	readDirErr error
}

func (f *originOpenedFileFixture) Stat() (os.FileInfo, error) {
	info, err := f.File.Stat()
	if f.afterStat != nil {
		f.afterStat()
	}
	if f.statErr != nil {
		return nil, f.statErr
	}
	return info, err
}
func (f *originOpenedFileFixture) Close() error { return errors.Join(f.File.Close(), f.closeErr) }

func TestRuntimeRootStorageReadBoundsGrowthAndCheckedClose(t *testing.T) {
	for _, mode := range []string{"exact", "overflow", "growth", "stat-error", "close-error", "cancel", "cancel-close"} {
		t.Run(mode, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "blob")
			value := []byte("12345678")
			if mode == "overflow" {
				value = append(value, '9')
			}
			if err := os.WriteFile(name, value, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			fixture := &originOpenedFileFixture{File: file}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "growth":
				fixture.afterStat = func() {
					// Stat already returned the actual FD's old size; the same
					// inode grows before Read, so a size-only check is inadequate.
					if err := os.WriteFile(name, []byte("123456789"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			case "stat-error":
				fixture.statErr = os.ErrNotExist
			case "close-error":
				fixture.closeErr = os.ErrNotExist
			case "cancel":
				cancel()
			case "cancel-close":
				cancel()
				fixture.closeErr = os.ErrClosed
			}
			actual, err := originReadOpenedFile(ctx, fixture, 8)
			switch mode {
			case "exact":
				if err != nil || !bytes.Equal(actual, value) {
					t.Fatal("exact bound rejected", actual, err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) || originStorageIsUnsafe(err) {
					t.Fatal("confirmed close changed benign cancellation", err)
				}
			default:
				if !originStorageIsUnsafe(err) || actual != nil || errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrClosed) || errors.Is(err, context.Canceled) {
					t.Fatal("unsafe read was successful/filterable", actual, err)
				}
			}
			if _, err = file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("real reader FD not closed", err)
			}
		})
	}
}

func TestRuntimeRootStorageBlobLimitAndSpecialTypeAreSticky(t *testing.T) {
	for _, mode := range []string{"sparse-overflow", "directory", "store-overflow"} {
		t.Run(mode, func(t *testing.T) {
			root, err := originOpenStorageRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			storage := &originRootStorage{root: root}
			switch mode {
			case "sparse-overflow":
				file, openErr := root.Create("blob")
				if openErr != nil {
					t.Fatal(openErr)
				}
				if err = errors.Join(file.Truncate(originStorageBlobLimit+1), file.Close()); err != nil {
					t.Fatal(err)
				}
				_, err = storage.Load(t.Context(), "blob")
			case "directory":
				if err = root.Mkdir("blob", 0o700); err != nil {
					t.Fatal(err)
				}
				_, err = storage.Load(t.Context(), "blob")
			case "store-overflow":
				err = storage.Store(t.Context(), "blob", make([]byte, originStorageBlobLimit+1))
			}
			if !originStorageIsUnsafe(err) || storage.Close() == nil {
				t.Fatal("unsafe blob lost owner uncertainty", err)
			}
			if err = storage.Store(t.Context(), "after", []byte("blocked")); !originStorageIsUnsafe(err) {
				t.Fatal("unsafe storage allowed later writes", err)
			}
			if _, err = root.Stat("after"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("sticky owner wrote another object", err)
			}
			if _, err = root.Stat("."); err != nil {
				t.Fatal("unknown owner released root", err)
			}
		})
	}
}

func TestRuntimeRootStorageLeaseReadBoundPreservesLegacyRecovery(t *testing.T) {
	for _, mode := range []string{"exact-fresh", "oversize-stale", "invalid", "stale", "empty"} {
		t.Run(mode, func(t *testing.T) {
			root, err := originOpenStorageRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			storage := &originRootStorage{root: root}
			if err = root.Mkdir("locks", 0o700); err != nil {
				t.Fatal(err)
			}
			updated := time.Now()
			if mode == "stale" || mode == "oversize-stale" {
				updated = updated.Add(-time.Minute)
			}
			marker, err := json.Marshal(originLockMeta{Created: updated, Updated: updated})
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "exact-fresh":
				marker = append(marker, bytes.Repeat([]byte(" "), originStorageLeaseLimit-len(marker))...)
			case "oversize-stale":
				marker = append(marker, bytes.Repeat([]byte(" "), originStorageLeaseLimit+1-len(marker))...)
			case "invalid":
				marker = []byte("{invalid")
			case "empty":
				marker = nil
			}
			name := "locks/issuer.lock"
			if err = root.WriteFile(name, marker, 0o600); err != nil {
				t.Fatal(err)
			}
			deadline := 4 * time.Second
			if mode == "exact-fresh" {
				deadline = 20 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), deadline)
			defer cancel()
			err = storage.Lock(ctx, "issuer")
			switch mode {
			case "stale", "empty":
				if err != nil {
					t.Fatal("legacy lease recovery failed", err)
				}
				if err = storage.Unlock(t.Context(), "issuer"); err != nil {
					t.Fatal(err)
				}
				if err = storage.Close(); err != nil {
					t.Fatal("recovered lease did not release", err)
				}
			case "exact-fresh":
				if !errors.Is(err, context.DeadlineExceeded) || originStorageIsUnsafe(err) {
					t.Fatal("exact-cap lease was stolen or rejected", err)
				}
				actual, readErr := root.ReadFile(name)
				if readErr != nil || !bytes.Equal(actual, marker) {
					t.Fatal("live lease changed", readErr)
				}
				if err = storage.Close(); err != nil {
					t.Fatal("benign lease wait cancellation retained root", err)
				}
			default:
				if !originStorageIsUnsafe(err) || storage.Close() == nil {
					t.Fatal("invalid marker was not safety-sticky", err)
				}
				actual, readErr := root.ReadFile(name)
				if readErr != nil || !bytes.Equal(actual, marker) {
					t.Fatal("unsafe marker was deleted/replaced as stale", readErr)
				}
			}
		})
	}
}

func TestRuntimeRootStorageListPreservesOrderAndSymlinkRules(t *testing.T) {
	dir := t.TempDir()
	root, err := originOpenStorageRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	storage := &originRootStorage{root: root}
	if err = root.Mkdir("d", 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "d/z", "z"} {
		if err = storage.Store(t.Context(), name, []byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Symlink("d", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	for _, recursive := range []bool{false, true} {
		keys, listErr := storage.List(t.Context(), "", recursive)
		want := []string{"a", "d", "link", "z"}
		if recursive {
			want = []string{"a", "d", "d/z", "link", "z"}
		}
		if listErr != nil || !slices.Equal(keys, want) {
			t.Fatal("list behavior changed", recursive, keys, listErr)
		}
	}
	if err = os.Symlink("a", filepath.Join(dir, "file-link")); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"a", "file-link"} {
		keys, listErr := storage.List(t.Context(), prefix, true)
		if listErr != nil || len(keys) != 0 {
			t.Fatal("list returned its starting regular file", keys, listErr)
		}
	}
	if err = root.Mkdir("d/nested", 0o700); err != nil {
		t.Fatal(err)
	}
	if err = storage.Store(t.Context(), "d/nested/leaf", []byte("nested")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("nested", filepath.Join(dir, "d", "child")); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"d", "link"} {
		for _, recursive := range []bool{false, true} {
			keys, listErr := storage.List(t.Context(), prefix, recursive)
			want := []string{prefix + "/child", prefix + "/nested", prefix + "/z"}
			if recursive {
				want = []string{prefix + "/child", prefix + "/nested", prefix + "/nested/leaf", prefix + "/z"}
			}
			if listErr != nil || !slices.Equal(keys, want) {
				t.Fatal("list lost followed prefix, lexical order or child symlink boundary", prefix, recursive, keys, listErr)
			}
		}
	}
	if err = os.Symlink("missing", filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"missing", "dangling"} {
		keys, listErr := storage.List(t.Context(), prefix, true)
		if !errors.Is(listErr, os.ErrNotExist) || len(keys) != 0 {
			t.Fatal("list hid missing prefix or dangling-link error", prefix, keys, listErr)
		}
	}
	if _, err = storage.List(t.Context(), "../escape", true); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("list accepted invalid FS path", err)
	}
}

// Err's second call is the post-close/pre-rename cancellation boundary in
// Store. Move the actual closed temp file there to make retirement uncertain.
type originStoreCancelFixture struct {
	context.Context
	calls      int
	afterClose func()
}

func (c *originStoreCancelFixture) Err() error {
	c.calls++
	if c.calls == 2 {
		c.afterClose()
	}
	return c.Context.Err()
}

func TestRuntimeRootStorageWriteCloseAndTempRetirementStayUnknown(t *testing.T) {
	root, err := originOpenStorageRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.Create("close-error")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &originOpenedFileFixture{File: file, closeErr: os.ErrClosed}
	err = originWriteAndClose(fixture, []byte("confirmed write, unconfirmed close"))
	if !originStorageIsUnsafe(err) || errors.Is(err, os.ErrClosed) {
		t.Fatal("temp close error was filterable", err)
	}
	if _, err = file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("underlying descriptor not closed", err)
	}
	storage := &originRootStorage{root: root}
	ctxBase, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &originStoreCancelFixture{Context: ctxBase, afterClose: func() {
		entries, readErr := storage.readDirectory(t.Context(), ".")
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, entry := range entries {
			if entry.Name() != "close-error" {
				if err := root.Rename(entry.Name(), "moved-temp"); err != nil {
					t.Fatal("temp FD was not closed before cancellation", err)
				}
			}
		}
		cancel()
	}}
	err = storage.Store(ctx, "blob", []byte("partial"))
	if !originStorageIsUnsafe(err) || errors.Is(err, context.Canceled) || storage.Close() == nil {
		t.Fatal("temp retirement uncertainty was filtered", err)
	}
	if _, err = root.Stat("moved-temp"); err != nil {
		t.Fatal("fixture did not exercise real temp retirement", err)
	}
}

func TestRuntimeRootStorageExactBlobLimitRoundTrips(t *testing.T) {
	root, err := originOpenStorageRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.Create("blob")
	if err != nil {
		t.Fatal(err)
	}
	if err = errors.Join(file.Truncate(originStorageBlobLimit), file.Close()); err != nil {
		t.Fatal(err)
	}
	storage := &originRootStorage{root: root}
	value, err := storage.Load(t.Context(), "blob")
	if err != nil || len(value) != originStorageBlobLimit {
		t.Fatal("exact new blob boundary rejected", len(value), err)
	}
	if err = storage.Store(t.Context(), "copy", value); err != nil {
		t.Fatal("exact boundary could not be stored", err)
	}
	if err = storage.Close(); err != nil {
		t.Fatal("valid bounded blob retained unknown root", err)
	}
}

func (f *originOpenedFileFixture) ReadDir(n int) ([]os.DirEntry, error) {
	if f.readDirErr != nil {
		return nil, f.readDirErr
	}
	return f.File.ReadDir(n)
}

func TestRuntimeRootStorageDirectoryReadChecksTypeAndClose(t *testing.T) {
	for _, mode := range []string{"regular", "stat-error", "read-error", "close-error", "cancel-close"} {
		t.Run(mode, func(t *testing.T) {
			name := t.TempDir()
			if mode == "regular" {
				name = filepath.Join(name, "blob")
				if err := os.WriteFile(name, []byte("data"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			file, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			fixture := &originOpenedFileFixture{File: file}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "stat-error":
				fixture.statErr = os.ErrNotExist
			case "read-error":
				fixture.readDirErr = os.ErrClosed
			case "close-error":
				fixture.closeErr = os.ErrClosed
			case "cancel-close":
				cancel()
				fixture.closeErr = context.Canceled
			}
			entries, err := originReadOpenedDirectory(ctx, fixture)
			if !originStorageIsUnsafe(err) || entries != nil || errors.Is(err, os.ErrNotExist) || errors.Is(err, context.Canceled) || errors.Is(err, os.ErrClosed) {
				t.Fatal("directory safety error became benign", entries, err)
			}
			if _, err = file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("actual directory probe FD leaked", err)
			}
		})
	}
}

func TestRuntimeRootStorageConfirmedCanceledTempCleanupReleasesRoot(t *testing.T) {
	root, err := originOpenStorageRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	storage := &originRootStorage{root: root}
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &originStoreCancelFixture{Context: base, afterClose: cancel}
	err = storage.Store(ctx, "blob", []byte("canceled before rename"))
	if !errors.Is(err, context.Canceled) || originStorageIsUnsafe(err) || storage.failure() != nil {
		t.Fatal("confirmed cleanup became unknown", err)
	}
	entries, err := storage.List(t.Context(), "", true)
	if err != nil || len(entries) != 0 {
		t.Fatal("confirmed cancel left a target or temp file", entries, err)
	}
	if err = storage.Close(); err != nil {
		t.Fatal("confirmed cancel failed to release directory", err)
	}
}
