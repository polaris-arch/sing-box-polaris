// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_logtail

package tsnet

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/tailscale/logtail/filch"
	"github.com/sagernet/tailscale/util/dirscope"
)

func TestCloseLogBufferReleasesOriginalOwnerOnce(t *testing.T) {
	scope := new(dirscope.Scope)
	release, err := scope.Begin()
	if err != nil {
		t.Fatal(err)
	}
	buffer, err := filch.New(filepath.Join(t.TempDir(), "log"), filch.Options{})
	if err != nil {
		release()
		t.Fatal(err)
	}
	var calls atomic.Int32
	s := &Server{
		directoryScope: scope,
		logbuffer: buffer,
		logbufferRelease: func() { calls.Add(1); release() },
	}
	if _, err := buffer.Write([]byte("before close")); err != nil {
		t.Fatal(err)
	}
	scope.Seal()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); s.closeLogBuffer() }()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("release calls = %d", calls.Load())
	}
	if _, err := buffer.Write([]byte("after close")); err == nil {
		t.Fatal("closed filch admitted a write")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := scope.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}
