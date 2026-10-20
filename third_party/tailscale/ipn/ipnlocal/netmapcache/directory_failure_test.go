// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmapcache

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sagernet/tailscale/util/dirscope"
)

func TestDirectoryStoreWriteFailureIsSticky(t *testing.T) {
	scope := new(dirscope.Scope)
	store := WithDirectoryScope(FileStore(filepath.Join(t.TempDir(), "absent")), scope)
	if err := store.Store(context.Background(), "key", []byte("value")); err == nil {
		t.Fatal("write unexpectedly succeeded")
	}
	scope.Seal()
	if err := scope.Wait(context.Background()); !errors.Is(err, dirscope.ErrIncomplete) {
		t.Fatalf("failed file write permitted retirement: %v", err)
	}
}
