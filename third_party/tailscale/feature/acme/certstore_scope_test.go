// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/tailscale/util/dirscope"
)

func TestCertFileStoreSealedLeaves(t *testing.T) {
	scope := new(dirscope.Scope)
	dir := t.TempDir()
	f := certFileStore{dir: dir, scope: scope}
	if err := f.WriteACMEKey([]byte("original")); err != nil {
		t.Fatal(err)
	}
	scope.Seal()
	if err := scope.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func() error{
		"account read": func() error { _, err := f.ACMEKey(); return err },
		"cert read": func() error { _, err := f.Read("example.test", time.Now()); return err },
		"account write": func() error { return f.WriteACMEKey([]byte("changed")) },
		"cert write": func() error { return f.WriteCert("example.test", []byte("cert")) },
		"key write": func() error { return f.WriteKey("example.test", []byte("key")) },
		"pair write": func() error { return f.WriteTLSCertAndKey("example.test", []byte("cert"), []byte("key")) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := fn(); !errors.Is(err, dirscope.ErrSealed) {
				t.Fatalf("sealed operation returned %v", err)
			}
		})
	}
	b, err := os.ReadFile(filepath.Join(dir, acmePEMName))
	if err != nil || string(b) != "original" {
		t.Fatalf("late account write changed file: %q, %v", b, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("late cert/key write created files: %v, %v", entries, err)
	}
}

func TestCertFileStoreLegacy(t *testing.T) {
	f := certFileStore{dir: t.TempDir()}
	if err := f.WriteTLSCertAndKey("example.test", []byte("cert"), []byte("key")); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteACMEKey([]byte("account")); err != nil {
		t.Fatal(err)
	}
	if b, err := f.ACMEKey(); err != nil || string(b) != "account" {
		t.Fatalf("legacy account key = %q, %v", b, err)
	}
}
