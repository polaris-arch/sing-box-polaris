// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmapcache

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/tailscale/util/dirscope"
)

// WithDirectoryScope binds the instance capability, including lazy IO.
func WithDirectoryScope(store Store, scope *dirscope.Scope) Store {
	if fs, ok := store.(FileStore); ok && scope != nil {
		store = directoryFileStore{FileStore: fs, scope: scope}
	}
	return directoryStore{store: store, scope: scope}
}

type directoryStore struct {
	store Store
	scope *dirscope.Scope
}

func (s directoryStore) List(ctx context.Context, prefix string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		release, err := s.scope.Begin()
		if err != nil { yield("", err); return }
		defer release()
		s.store.List(ctx, prefix)(yield)
	}
}
func (s directoryStore) Load(ctx context.Context, key string) ([]byte, error) {
	release, err := s.scope.Begin()
	if err != nil { return nil, err }
	defer release()
	return s.store.Load(ctx, key)
}
func (s directoryStore) Store(ctx context.Context, key string, value []byte) error {
	release, err := s.scope.Begin()
	if err != nil { return err }
	defer release()
	return s.scope.RecordWriteError(s.store.Store(ctx, key, value))
}
func (s directoryStore) Remove(ctx context.Context, key string) error {
	release, err := s.scope.Begin()
	if err != nil { return err }
	defer release()
	return s.store.Remove(ctx, key)
}

// directoryFileStore retains FileStore's layout and write/remove behavior, but
// makes file/directory Close errors visible for the scoped reader. The outer
// directoryStore owns the operation token, including iteration and Close.
type directoryFileStore struct {
	FileStore
	scope *dirscope.Scope
}

func (s directoryFileStore) Load(ctx context.Context, key string) ([]byte, error) {
	data, err := s.scope.ReadFile(filepath.Join(string(s.FileStore), hex.EncodeToString([]byte(key))))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("key %q not found: %w", key, ErrKeyNotFound)
	}
	return data, err
}

func (s directoryFileStore) List(ctx context.Context, prefix string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		entries, err := s.scope.ReadDir(string(s.FileStore))
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			yield("", err)
			return
		}
		for _, entry := range entries {
			key, err := hex.DecodeString(entry.Name())
			if err != nil {
				yield("", err)
				return
			}
			name := string(key)
			if strings.HasPrefix(name, prefix) && !yield(name, nil) {
				return
			}
		}
	}
}
