// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/tailscale/util/dirscope"
)

func TestScopedFileStoreRejectsConstructionAfterSeal(t *testing.T) {
	scope := new(dirscope.Scope)
	scope.Seal()
	path := filepath.Join(t.TempDir(), "uncreated", "prefs")
	if _, err := NewFileStoreWithScope(t.Logf, path, scope); !errors.Is(err, dirscope.ErrSealed) {
		t.Fatalf("constructor error = %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("sealed constructor created or inspected unexpected directory: %v", err)
	}
}

func TestScopedFileStoreRejectsLateReadAndWrite(t *testing.T) {
	scope := new(dirscope.Scope)
	path := filepath.Join(t.TempDir(), "state")
	s, err := NewFileStoreWithScope(t.Logf, path, scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState("prefs", []byte("old")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	scope.Seal()
	if err := scope.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadState("prefs"); !errors.Is(err, dirscope.ErrSealed) {
		t.Fatalf("late read = %v", err)
	}
	if err := s.WriteState("prefs", []byte("new")); !errors.Is(err, dirscope.ErrSealed) {
		t.Fatalf("late write = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("sealed store changed disk: %v", err)
	}
}

func TestFileStoreLegacyAndScopeIdentity(t *testing.T) {
	root := t.TempDir()
	legacy, err := NewFileStore(t.Logf, filepath.Join(root, "legacy"))
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.WriteState("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	oldScope, otherScope := new(dirscope.Scope), new(dirscope.Scope)
	bound, err := NewFileStoreWithScope(t.Logf, filepath.Join(root, "bound"), oldScope)
	if err != nil {
		t.Fatal(err)
	}
	otherScope.Seal()
	if err := bound.WriteState("k", []byte("v")); err != nil {
		t.Fatal("unrelated scope affected existing store:", err)
	}
	oldScope.Seal()
	if err := bound.WriteState("k", []byte("v2")); !errors.Is(err, dirscope.ErrSealed) {
		t.Fatalf("original bound scope not enforced: %v", err)
	}
}
