// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/tailscale/util/dirscope"
)

func TestFileStoreAtomicWriteFailureIsSticky(t *testing.T) {
	scope := new(dirscope.Scope)
	path := filepath.Join(t.TempDir(), "state")
	s, err := NewFileStoreWithScope(t.Logf, path, scope)
	if err != nil { t.Fatal(err) }
	// Replace this test-only destination with a directory so atomic rename fails.
	if err := os.Remove(path); err != nil { t.Fatal(err) }
	if err := os.Mkdir(path, 0o700); err != nil { t.Fatal(err) }
	if err := s.WriteState("key", []byte("value")); err == nil { t.Fatal("write unexpectedly succeeded") }
	scope.Seal()
	if err := scope.Wait(context.Background()); !errors.Is(err, dirscope.ErrIncomplete) {
		t.Fatalf("failed atomic write permitted retirement: %v", err)
	}
}
