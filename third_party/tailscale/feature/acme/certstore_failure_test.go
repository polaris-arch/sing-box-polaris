// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sagernet/tailscale/util/dirscope"
)

func TestCertAtomicWriteFailureIsSticky(t *testing.T) {
	scope := new(dirscope.Scope)
	f := certFileStore{dir: filepath.Join(t.TempDir(), "absent"), scope: scope}
	if err := f.WriteTLSCertAndKey("example.test", []byte("cert"), []byte("key")); err == nil {
		t.Fatal("expected atomic write failure")
	}
	scope.Seal()
	if err := scope.Wait(context.Background()); !errors.Is(err, dirscope.ErrIncomplete) {
		t.Fatalf("failed atomic write permitted retirement: %v", err)
	}
}
