package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	box "github.com/sagernet/sing-box"
)

type (
	runtimePersistenceBinding struct {
		persist   func(box.RuntimeIdentity, []byte) error
		mode      string
		retrySafe bool
	}
	runtimePersistenceContextKey struct{}
)

// ContextWithRuntimePersistence binds only this authenticated start request.
// It does not mutate a service-global callback or acquire its lifecycle lock.
func ContextWithRuntimePersistence(ctx context.Context, persist func(box.RuntimeIdentity, []byte) error) context.Context {
	return context.WithValue(ctx, runtimePersistenceContextKey{}, runtimePersistenceBinding{persist: persist, mode: "owner_acknowledged"})
}

// ContextWithRuntimePersistenceMode captures a fixed host contract per instance.
func ContextWithRuntimePersistenceMode(ctx context.Context, persist func(box.RuntimeIdentity, []byte) error, mode string) (context.Context, error) {
	return ContextWithRuntimePersistenceOptions(ctx, persist, mode, false)
}

// retrySafe promises same-identity replay even after partial callback success.
func ContextWithRuntimePersistenceOptions(ctx context.Context, persist func(box.RuntimeIdentity, []byte) error, mode string, retrySafe bool) (context.Context, error) {
	switch mode {
	case "owner_acknowledged", "exact_configuration_file", "app_authoritative_regeneration":
	default:
		return nil, errors.New("unsupported runtime persistence mode")
	}
	return context.WithValue(ctx, runtimePersistenceContextKey{}, runtimePersistenceBinding{persist: persist, mode: mode, retrySafe: retrySafe}), nil
}

func runtimePersistenceRetrySafeForRequest(ctx context.Context) bool {
	if ctx != nil {
		if binding, ok := ctx.Value(runtimePersistenceContextKey{}).(runtimePersistenceBinding); ok {
			return binding.retrySafe
		}
	}
	return false
}

func runtimePersistenceModeForRequest(ctx context.Context) string {
	if ctx != nil {
		if binding, ok := ctx.Value(runtimePersistenceContextKey{}).(runtimePersistenceBinding); ok {
			return binding.mode
		}
	}
	return "owner_acknowledged"
}

func runtimePersistenceForRequest(ctx context.Context, fallback func(box.RuntimeIdentity, []byte) error) func(box.RuntimeIdentity, []byte) error {
	if ctx != nil {
		if binding, ok := ctx.Value(runtimePersistenceContextKey{}).(runtimePersistenceBinding); ok {
			return binding.persist
		}
	}
	return fallback
}

type runtimeFilePersistence struct {
	mu          sync.Mutex
	path        string
	expected    []byte
	incarnation string
	write       func(string, []byte, []byte) (bool, error)
}

// NewRuntimeFilePersistence captures an existing host's authoritative restart
// path and exact startup bytes. The caller owns that source; this is not a
// facility for assigning a path to stdin, merged profiles or App diagnostics.
// No file is changed during binding. A source changed outside this owner causes
// an explicit post-publication durability error, never a runtime rollback.
func NewRuntimeFilePersistence(path string, initial []byte) (func(box.RuntimeIdentity, []byte) error, error) {
	if path == "" {
		return nil, errors.New("runtime persistence source is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	p := &runtimeFilePersistence{path: absolute, expected: append([]byte(nil), initial...), write: writeRuntimeOwnedFile}
	return p.persist, nil
}

func (p *runtimeFilePersistence) persist(identity box.RuntimeIdentity, content []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if identity.Incarnation == "" {
		return errors.New("runtime persistence identity is empty")
	}
	if p.incarnation != "" && p.incarnation != identity.Incarnation {
		return errors.New("runtime persistence belongs to another instance")
	}
	p.incarnation = identity.Incarnation
	renamed, err := p.write(p.path, p.expected, content)
	// Rename has changed the source even if directory sync subsequently fails.
	// Retain that exact expected content for retry; do not acknowledge durability.
	if renamed {
		p.expected = append([]byte(nil), content...)
	}
	return err
}

func readRuntimeOwnedFile(path string, expected []byte) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("runtime persistence source is not a regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(content, expected) {
		return nil, errors.New("runtime persistence source changed outside its owner")
	}
	return info, nil
}

func writeRuntimeOwnedFile(path string, expected, content []byte) (renamed bool, result error) {
	info, err := readRuntimeOwnedFile(path, expected)
	if err != nil {
		return false, err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".runtime-config-*")
	if err != nil {
		return false, err
	}
	name := file.Name()
	closed := false
	defer func() {
		if !closed {
			result = errors.Join(result, file.Close())
		}
		if !renamed {
			if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
				result = errors.Join(result, err)
			}
		}
	}()
	if err = prepareRuntimeFileMetadata(path, file, info); err != nil {
		return false, err
	}
	n, err := file.Write(content)
	if err != nil {
		return false, err
	}
	if n != len(content) {
		return false, io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return false, err
	}
	closed = true
	if err = file.Close(); err != nil {
		return false, err
	}
	// Detect replacement or edits made while preparing the temporary file.
	current, err := readRuntimeOwnedFile(path, expected)
	if err != nil {
		return false, err
	}
	if !os.SameFile(info, current) || info.Mode() != current.Mode() {
		return false, errors.New("runtime persistence source identity changed")
	}
	return replaceRuntimeOwnedFile(name, path)
}

// Flush errors after successful replacement must retain the new expected bytes.
// This seam also permits deterministic regression fixtures without native I/O.
func replaceAndFlushRuntimeFile(source, destination string, replace func(string, string) error, flush func(string) error) (bool, error) {
	if err := replace(source, destination); err != nil {
		return false, err
	}
	return true, flush(destination)
}
