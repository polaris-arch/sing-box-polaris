package originca

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter/certificate"

	"github.com/caddyserver/certmagic"
)

// Runtime storage holds a directory capability, not its configurable alias.
// Only OriginCA's runtime path uses this backend. Legacy FileStorage layout,
// lock names/JSON and five-second heartbeat/ten-second stale lease are retained
// so an older process sharing the cache still observes the same protocol.
// Unlike FileStorage, every heartbeat has an explicit stop and real join.
// Runtime-only safety limits are 32 MiB per cache blob and 4 KiB per lease
// marker. These are new bounds, not limits promised by legacy FileStorage.
const (
	originStorageBlobLimit  = 32 << 20
	originStorageLeaseLimit = 4096
)

type originRootStorage struct {
	root  *os.Root
	mu    sync.Mutex
	locks map[string]*originRootLock
	err   error
}
type originRootLock struct {
	file       *os.File
	identity   os.FileInfo
	stop, done chan struct{}
}
type originLockMeta struct {
	Created time.Time `json:"created,omitempty"`
	Updated time.Time `json:"updated,omitempty"`
}

var _ certmagic.Storage = (*originRootStorage)(nil)

func (s *originRootStorage) failure() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *originRootStorage) failed(err error) {
	if err != nil {
		s.mu.Lock()
		s.err = errors.Join(s.err, originStorageUnsafe(err))
		s.mu.Unlock()
	}
}

// Deliberately opaque: Scope must not filter an unconfirmed close/type/read as
// benign cancellation/closure, and cache lookup must not turn it into a miss.
type originStorageSafetyError struct{ cause error }

func (e *originStorageSafetyError) Error() string {
	return "origin CA runtime storage safety unconfirmed: " + e.cause.Error()
}
func (*originStorageSafetyError) RuntimeCleanupIncomplete() bool { return true }

func originStorageUnsafe(err error) error {
	if err == nil {
		return nil
	}
	return &originStorageSafetyError{cause: err}
}

func originStorageIsUnsafe(err error) bool {
	var unsafe *originStorageSafetyError
	return errors.As(err, &unsafe)
}

func (s *originRootStorage) unsafe(err error) error {
	err = originStorageUnsafe(err)
	s.failed(err)
	return err
}

func (s *originRootStorage) Store(ctx context.Context, key string, value []byte) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = s.failure(); err != nil {
		return err
	}
	if len(value) > originStorageBlobLimit {
		return s.unsafe(fmt.Errorf("cache blob exceeds %d bytes", originStorageBlobLimit))
	}
	dir := path.Dir(key)
	if err = s.root.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var token [16]byte
	if _, err = rand.Read(token[:]); err != nil {
		return err
	}
	temporary := path.Join(dir, ".origin-ca-"+hex.EncodeToString(token[:]))
	file, err := s.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if removeErr := s.root.Remove(temporary); removeErr != nil {
				err = s.unsafe(errors.Join(err, removeErr))
			}
		}
	}()
	err = originWriteAndClose(file, value)
	if originStorageIsUnsafe(err) {
		s.failed(err)
	}
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return s.root.Rename(temporary, key)
}

func originWriteAndClose(file interface {
	io.WriteCloser
	Sync() error
}, value []byte,
) error {
	_, writeErr := file.Write(value)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if closeErr != nil {
		return originStorageUnsafe(errors.Join(writeErr, closeErr))
	}
	return writeErr
}

func (s *originRootStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.failure(); err != nil {
		return nil, err
	}
	return s.readFile(ctx, key, originStorageBlobLimit)
}

type originStorageReader interface {
	io.Reader
	Stat() (os.FileInfo, error)
	Close() error
}

type originStorageContextReader struct {
	ctx context.Context
	io.Reader
}

func (r originStorageContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(buffer)
}

// Production supplies the actual opened *os.File. Stat and data always come
// from that same handle; size is only an early rejection, not the read bound.
func originReadOpenedFile(ctx context.Context, file originStorageReader, limit int64) (value []byte, err error) {
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = originStorageUnsafe(errors.Join(err, closeErr))
			value = nil
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, originStorageUnsafe(err)
	}
	if !info.Mode().IsRegular() {
		return nil, originStorageUnsafe(fmt.Errorf("byte read requires regular file, got %s", info.Mode()))
	}
	if info.Size() > limit {
		return nil, originStorageUnsafe(fmt.Errorf("file exceeds %d bytes", limit))
	}
	value, err = io.ReadAll(io.LimitReader(originStorageContextReader{ctx: ctx, Reader: file}, limit+1))
	if err != nil {
		if err == ctx.Err() {
			return nil, err
		}
		return nil, originStorageUnsafe(err)
	}
	if int64(len(value)) > limit {
		return nil, originStorageUnsafe(fmt.Errorf("file grew beyond %d bytes", limit))
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return value, nil
}

func (s *originRootStorage) readFile(ctx context.Context, key string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := s.root.OpenFile(key, originStorageReadFlags, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, s.unsafe(err)
	}
	value, err := originReadOpenedFile(ctx, file, limit)
	if originStorageIsUnsafe(err) {
		s.failed(err)
	}
	return value, err
}

func (s *originRootStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.failure(); err != nil {
		return err
	}
	return s.root.RemoveAll(key)
}

func (s *originRootStorage) Exists(ctx context.Context, key string) bool {
	if ctx.Err() != nil || s.failure() != nil {
		return false
	}
	_, err := s.root.Stat(key)
	return err == nil
}

func (s *originRootStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	if err := ctx.Err(); err != nil {
		return certmagic.KeyInfo{}, err
	}
	if err := s.failure(); err != nil {
		return certmagic.KeyInfo{}, err
	}
	info, err := s.root.Stat(key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	return certmagic.KeyInfo{Key: key, Modified: info.ModTime(), Size: info.Size(), IsTerminal: !info.IsDir()}, nil
}

func (s *originRootStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.failure(); err != nil {
		return nil, err
	}
	start := prefix
	if start == "" {
		start = "."
	}
	// WalkDir follows its starting prefix, including a directory symlink.
	// Child symlinks remain entries and are not recursively followed below.
	if !fs.ValidPath(start) || runtime.GOOS == "windows" && strings.Contains(start, `\`) {
		return nil, &fs.PathError{Op: "walk", Path: start, Err: fs.ErrInvalid}
	}
	// Metadata selects traversal only. readDirectory still opens with directory
	// flags and checks that actual FD, even if this name changes after Stat.
	info, err := s.root.Stat(start)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, s.unsafe(fmt.Errorf("list prefix is a special object: %s", info.Mode()))
		}
		return nil, nil
	}
	return originListDirectory(ctx, start, recursive, s.readDirectory)
}

func originListDirectory(ctx context.Context, start string, recursive bool, readDirectory func(context.Context, string) ([]os.DirEntry, error)) ([]string, error) {
	var keys []string
	var walk func(string) error
	walk = func(directory string) error {
		entries, err := readDirectory(ctx, directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err = ctx.Err(); err != nil {
				return err
			}
			key := path.Join(directory, entry.Name())
			keys = append(keys, key)
			if recursive && entry.IsDir() {
				if err = walk(key); err != nil {
					return err
				}
			}
		}
		return nil
	}
	err := walk(start)
	return keys, err
}

func (s *originRootStorage) readDirectory(ctx context.Context, key string) (entries []os.DirEntry, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	file, err := s.root.OpenFile(key, originStorageDirectoryFlags, 0)
	if err != nil {
		return nil, s.unsafe(err)
	}
	entries, err = originReadOpenedDirectory(ctx, file)
	if originStorageIsUnsafe(err) {
		s.failed(err)
	}
	return entries, err
}

type originStorageDirectoryReader interface {
	Stat() (os.FileInfo, error)
	ReadDir(int) ([]os.DirEntry, error)
	Close() error
}

func originReadOpenedDirectory(ctx context.Context, file originStorageDirectoryReader) (entries []os.DirEntry, err error) {
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = originStorageUnsafe(errors.Join(err, closeErr))
			entries = nil
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, originStorageUnsafe(err)
	}
	if !info.IsDir() {
		return nil, originStorageUnsafe(fmt.Errorf("directory read requires directory, got %s", info.Mode()))
	}
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		batch, readErr := file.ReadDir(128)
		entries = append(entries, batch...)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, originStorageUnsafe(readErr)
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

func originWriteLock(file *os.File, created time.Time) error {
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(originLockMeta{Created: created, Updated: time.Now()}); err != nil {
		return err
	}
	return file.Sync()
}

func (s *originRootStorage) Lock(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.failure(); err != nil {
		return err
	}
	name := path.Join("locks", certmagic.StorageKeys.Safe(key)+".lock")
	if err := s.root.MkdirAll("locks", 0o700); err != nil {
		return err
	}
	emptyCount := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.failure(); err != nil {
			return err
		}
		file, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644)
		if err == nil {
			created := time.Now()
			writeErr := originWriteLock(file, created)
			info, statErr := file.Stat()
			if statErr == nil && !info.Mode().IsRegular() {
				statErr = errors.New("new origin CA lease is not a regular file")
			}
			err = errors.Join(writeErr, statErr)
			if err != nil {
				err = errors.Join(err, file.Close(), s.root.Remove(name))
				return s.unsafe(err)
			}
			lock := &originRootLock{file: file, identity: info, stop: make(chan struct{}), done: make(chan struct{})}
			s.mu.Lock()
			if s.locks == nil {
				s.locks = make(map[string]*originRootLock)
			}
			s.locks[name] = lock
			s.mu.Unlock()
			go s.maintainLock(name, created, lock)
			return nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		// Match FileStorage recovery of an empty crashed lease after eight polls;
		// malformed metadata still reports the actual cache repair need.
		value, readErr := s.readFile(ctx, name, originStorageLeaseLimit)
		if errors.Is(readErr, fs.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return readErr
		}
		var meta originLockMeta
		if len(value) == 0 {
			emptyCount++
			if emptyCount >= 8 {
				if err := s.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				continue
			}
		} else {
			if err = json.Unmarshal(value, &meta); err != nil {
				return s.unsafe(err)
			}
			updated := meta.Updated
			if updated.IsZero() {
				updated = meta.Created
			}
			if !updated.IsZero() && time.Since(updated) > 10*time.Second {
				if err = s.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				continue
			}
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *originRootStorage) maintainLock(name string, created time.Time, lock *originRootLock) {
	defer close(lock.done)
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-lock.stop:
			return
		case <-timer.C:
			current, err := certificate.RuntimeRootIdentity(s.root, name)
			if err == nil && !os.SameFile(current, lock.identity) {
				err = errors.New("origin CA cache lease identity changed")
			}
			if err == nil {
				err = originWriteLock(lock.file, created)
			}
			if err != nil {
				s.failed(err)
				return
			}
		}
	}
}

func (s *originRootStorage) Unlock(_ context.Context, key string) error {
	name := path.Join("locks", certmagic.StorageKeys.Safe(key)+".lock")
	s.mu.Lock()
	lock := s.locks[name]
	delete(s.locks, name)
	s.mu.Unlock()
	if lock == nil {
		return errors.New("origin CA cache lease was not held")
	}
	close(lock.stop)
	<-lock.done
	info, err := certificate.RuntimeRootIdentity(s.root, name)
	if err == nil && !os.SameFile(info, lock.identity) {
		err = errors.New("origin CA cache lease identity changed")
	}
	if err == nil {
		err = s.root.Remove(name)
	}
	err = errors.Join(err, lock.file.Close(), s.failure())
	s.failed(err)
	return err
}

func (s *originRootStorage) Close() error {
	s.mu.Lock()
	pending := len(s.locks) != 0
	err := s.err
	s.mu.Unlock()
	if pending || err != nil {
		return originStorageUnsafe(errors.Join(err, fmt.Errorf("origin CA cache directory cleanup remains unconfirmed (held leases: %t)", pending)))
	}
	if err = s.root.Close(); err != nil {
		return s.unsafe(err)
	}
	return nil
}
