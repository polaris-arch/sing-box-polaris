//go:build !windows

package cachefile

import (
	"os"
	"path/filepath"
	"sync"
)

// Preserve the original Unix permission boundary; no permissions are changed.
func requireRuntimeJournalCustody(_ string, info os.FileInfo, directory bool) (func() error, error) {
	mask := os.FileMode(0o077)
	if directory {
		mask = 0o022
	}
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm()&mask != 0 {
		return nil, ErrFakeIPRecoveryCustody
	}
	return func() error { return nil }, nil
}

type runtimeJournalRootCustody struct {
	access sync.Mutex
	info   os.FileInfo
	closed bool
}

func requireRuntimeJournalRootCustody(path string, info os.FileInfo) (*runtimeJournalRootCustody, error) {
	if _, err := requireRuntimeJournalCustody(path, info, true); err != nil {
		return nil, err
	}
	return &runtimeJournalRootCustody{info: info}, nil
}

func (r *runtimeJournalRootCustody) Close() error {
	r.access.Lock()
	defer r.access.Unlock()
	r.closed = true
	return nil
}

func (r *runtimeJournalRootCustody) RequireFile(path string, info os.FileInfo) (func() error, error) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return nil, ErrFakeIPRecoveryClosed
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !os.SameFile(parent, r.info) {
		return nil, ErrFakeIPRecoveryCustody
	}
	if _, err := requireRuntimeJournalCustody(filepath.Dir(path), parent, true); err != nil {
		return nil, err
	}
	return requireRuntimeJournalCustody(path, info, false)
}
