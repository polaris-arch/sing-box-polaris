package usagepersist

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/sagernet/sing/service/filemanager"
)

// ErrFileInUse means another live tracker already owns the snapshot. Serializing
// individual saves is insufficient: two loaded snapshots still lose updates.
var ErrFileInUse = errors.New("usage statistics file is already in use")

// FileLease is held from before Load until the final writer has completed. The
// sidecar must not be removed: unlinking a locked file permits a second inode
// and two simultaneous owners. The OS releases it after process termination.
// It coordinates cooperating writers, not arbitrary external file replacement.
type FileLease struct {
	Path        string
	ManagedPath string
	file        *os.File
	once        sync.Once
	closeErr    error
}

func AcquireFile(ctx context.Context, path string) (*FileLease, error) {
	if path == "" {
		return nil, errors.New("usage statistics path is empty")
	}
	absolute, err := filepath.Abs(filemanager.BasePath(ctx, path))
	if err != nil {
		return nil, err
	}
	// Resolve directory aliases before choosing the stable sidecar. Resolve an
	// existing final symlink too, and use this same path for all subsequent IO.
	canonical, err := filepath.EvalSymlinks(absolute)
	if os.IsNotExist(err) {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(absolute))
		if parentErr != nil {
			return nil, parentErr
		}
		canonical = filepath.Join(parent, filepath.Base(absolute))
	} else if err != nil {
		return nil, err
	}
	managed, err := managedUsagePath(ctx, canonical)
	if err != nil {
		return nil, err
	}
	file, err := filemanager.OpenFile(ctx, managed+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = lockUsageFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock usage statistics %q: %w", canonical, err)
	}
	return &FileLease{Path: canonical, ManagedPath: managed, file: file}, nil
}

func (l *FileLease) Close() error {
	l.once.Do(func() { l.closeErr = l.file.Close() })
	return l.closeErr
}

// FileManager paths are logical names, not necessarily native absolute paths.
// In particular, its default Windows implementation prepends a nonempty base
// even to drive-qualified paths. Never feed the resolved physical path back
// into that mapping without checking; retain a verified manager-relative name.
func managedUsagePath(ctx context.Context, canonical string) (string, error) {
	resolvesToCanonical := func(name string) bool {
		mapped, err := filepath.Abs(filemanager.BasePath(ctx, name))
		if err != nil {
			return false
		}
		// The parent exists even when the snapshot does not yet exist.
		parent, err := filepath.EvalSymlinks(filepath.Dir(mapped))
		if err != nil {
			return false
		}
		mapped = filepath.Join(parent, filepath.Base(mapped))
		if runtime.GOOS == "windows" {
			return strings.EqualFold(mapped, canonical)
		}
		return mapped == canonical
	}
	if resolvesToCanonical(canonical) {
		return canonical, nil
	}
	base, err := filepath.Abs(filemanager.BasePath(ctx, "."))
	if err != nil {
		return "", err
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(base, canonical)
	if err != nil {
		return "", err
	}
	if !resolvesToCanonical(relative) {
		return "", errors.New("file manager cannot address canonical usage statistics path")
	}
	return relative, nil
}
