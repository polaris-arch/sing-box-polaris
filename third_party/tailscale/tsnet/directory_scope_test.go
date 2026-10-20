// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/tailscale/util/dirscope"
)

func TestDirectoryScopeRejectsStartBeforeMkdir(t *testing.T) {
	scope := new(dirscope.Scope)
	scope.Seal()
	path := filepath.Join(t.TempDir(), "never-created")
	s := &Server{Dir: path, DirectoryScope: scope}
	if err := s.Start(); !errors.Is(err, dirscope.ErrSealed) {
		t.Fatalf("Start = %v", err)
	}
	defer s.shutdownCancel()
	if s.directoryScope != scope {
		t.Fatal("start did not capture original scope")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("sealed start created directory: %v", err)
	}
	// Exported fields cannot be changed after first use. Even accidental
	// mutation must not make initOnce replace the original captured owner.
	s.DirectoryScope = new(dirscope.Scope)
	if err := s.Start(); !errors.Is(err, dirscope.ErrSealed) || s.directoryScope != scope {
		t.Fatalf("second Start replaced original failed owner: %v", err)
	}
}

func TestDirectoryScopeFailedStartReleasesConstruction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file-not-directory")
	if err := os.WriteFile(path, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	scope := new(dirscope.Scope)
	s := &Server{Dir: path, DirectoryScope: scope}
	if err := s.Start(); err == nil {
		t.Fatal("expected directory creation error")
	}
	defer s.shutdownCancel()
	scope.Seal()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// No resource was constructed; the failed start token must be released.
	if err := scope.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestScopedCapturePcapRejectedWithoutFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	for name, s := range map[string]*Server{
		"before start": {DirectoryScope: new(dirscope.Scope)},
		"captured owner": {directoryScope: new(dirscope.Scope)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := s.CapturePcap(context.Background(), path); err == nil {
				t.Fatal("scoped capture was admitted")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("capture touched destination: %v", err)
			}
		})
	}
}
