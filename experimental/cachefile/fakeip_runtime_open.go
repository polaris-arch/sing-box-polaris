package cachefile

import (
	"context"
	"os"
	"path/filepath"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
)

type (
	fakeIPRuntimeOpenKey     struct{}
	fakeIPRuntimeOpenRequest struct {
		expected *adapter.FakeIPRuntimeBackendDescriptor
	}
)

// ContextWithFakeIPRuntimeOpen selects non-destructive opening for an explicitly
// configured cache. A nonnil expected descriptor requires that existing file's
// immutable identity; nil permits creating a NEW configured file exclusively.
// It grants no custody to paths read from another database. The coordinator must
// recover the root first, then use its known descriptor for a referenced path.
func ContextWithFakeIPRuntimeOpen(ctx context.Context, expected *adapter.FakeIPRuntimeBackendDescriptor) context.Context {
	request := fakeIPRuntimeOpenRequest{}
	if expected != nil {
		value := *expected
		request.expected = &value
	}
	return context.WithValue(ctx, fakeIPRuntimeOpenKey{}, request)
}

func fakeIPRuntimeOpenFromContext(ctx context.Context) (fakeIPRuntimeOpenRequest, bool) {
	request, found := ctx.Value(fakeIPRuntimeOpenKey{}).(fakeIPRuntimeOpenRequest)
	return request, found
}

func validateRuntimeOpenIdentity(path, cacheID string, request fakeIPRuntimeOpenRequest) error {
	if request.expected == nil {
		return nil
	}
	expected := request.expected
	if expected.DatabaseID == "" || expected.Path != path || expected.CacheID != cacheID {
		return ErrFakeIPRuntimeIdentity
	}
	return nil
}

func (c *CacheFile) startFakeIPRuntime(request fakeIPRuntimeOpenRequest) error {
	c.runtimeStrict.Store(true)
	path, err := filepath.Abs(c.path)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	if err = validateRuntimeOpenIdentity(path, c.cacheIDText, request); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && request.expected == nil {
		// The configured path grants creation, but never replacement or chmod.
		file, createErr := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return createErr
		}
		info, err = file.Stat()
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		err = syncRuntimeFileCreation(path)
	}
	if err != nil {
		return err
	}
	db, err := openStrictRuntimeDatabase(c.ctx, path, info)
	if err != nil {
		return err
	}
	if request.expected != nil {
		err = db.View(func(tx *bbolt.Tx) error {
			root, err := runtimeRoot(tx)
			if err != nil {
				return err
			}
			if string(root.Get(keyRuntimeIdentity)) != request.expected.DatabaseID {
				return ErrFakeIPRuntimeIdentity
			}
			return nil
		})
		if err != nil {
			_ = db.Close()
			return err
		}
	}
	c.DB = db
	c.runtimeFileInfo = info
	return nil
}

// Called at promotion/binding, outside manager admission locks. A renamed or
// replaced path cannot borrow the identity of the still-open old DB handle.
func (c *CacheFile) validateRuntimeFileIdentity() error {
	c.dbAccess.RLock()
	expected := c.runtimeFileInfo
	c.dbAccess.RUnlock()
	if expected == nil {
		return ErrFakeIPRecoveryCustody
	}
	actual, err := os.Lstat(c.path)
	if err != nil {
		return err
	}
	if !actual.Mode().IsRegular() || actual.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, actual) {
		return ErrFakeIPRuntimeIdentity
	}
	return nil
}
