// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dirscope

import (
	"errors"
	"io"
	"os"
	"sort"
)

// RecordWriteError records the result of an admitted filesystem write before
// its operation token is released. Helpers such as atomicfile.WriteFile do not
// distinguish write/rename errors from internal Close errors, so every error is
// conservatively sticky. Do not call this for Begin rejection: no IO ran then.
// This method neither acquires a token nor performs filesystem access.
func (s *Scope) RecordWriteError(err error) error {
	s.Fail(err)
	return err
}

// ReadFile admits, reads, and closes a file. Unlike
// os.ReadFile, a successful read cannot hide a failing Close. An Open failure
// acquired no handle and is returned without poisoning the scope (e.g. ENOENT
// is an ordinary cache miss). Nested use under an outer token is safe; sealing
// can reject the inner admission before it opens anything.
func (s *Scope) ReadFile(path string) ([]byte, error) {
	if s == nil {
		return os.ReadFile(path)
	}
	release, err := s.Begin()
	if err != nil {
		return nil, err
	}
	defer release()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return s.readAndClose(f)
}

func (s *Scope) readAndClose(r io.ReadCloser) ([]byte, error) {
	b, readErr := io.ReadAll(r)
	closeErr := r.Close()
	s.Fail(closeErr)
	return b, errors.Join(readErr, closeErr)
}

// ReadDir is the scoped counterpart of os.ReadDir. It preserves sorted output
// and records Close failure before releasing its operation token.
func (s *Scope) ReadDir(path string) ([]os.DirEntry, error) {
	if s == nil {
		return os.ReadDir(path)
	}
	release, err := s.Begin()
	if err != nil {
		return nil, err
	}
	defer release()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := f.ReadDir(-1)
	closeErr := f.Close()
	s.Fail(closeErr)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, errors.Join(readErr, closeErr)
}
