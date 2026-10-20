// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/tailscale/util/dirscope"
)

func TestChonkAtomicWriteFailureIsSticky(t *testing.T) {
	scope := new(dirscope.Scope)
	path := filepath.Join(t.TempDir(), "chonk")
	c, err := ChonkDirWithScope(path, scope)
	if err != nil { t.Fatal(err) }
	// Only this newly-created, empty test fixture is removed.
	if err := os.Remove(path); err != nil { t.Fatal(err) }
	if err := c.SetLastActiveAncestor(AUMHash{}); err == nil {
		t.Fatal("atomic write unexpectedly succeeded")
	}
	scope.Seal()
	if err := scope.Wait(context.Background()); !errors.Is(err, dirscope.ErrIncomplete) {
		t.Fatalf("failed atomic write permitted retirement: %v", err)
	}
}
