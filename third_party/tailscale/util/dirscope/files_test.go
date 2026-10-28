// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dirscope

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingCloseReader struct {
	io.Reader
	closeFn func() error
}

func (r failingCloseReader) Close() error { return r.closeFn() }

func TestReadCloseFailurePoisonsBeforeRelease(t *testing.T) {
	scope := new(Scope)
	release, err := scope.Begin()
	if err != nil { t.Fatal(err) }
	scope.Seal()
	closeFailure := errors.New("injected close failure")
	data, err := scope.readAndClose(failingCloseReader{
		Reader: strings.NewReader("complete data"),
		closeFn: func() error {
			select {
			case <-scope.Done(): t.Fatal("resource token released before Close")
			default:
			}
			return closeFailure
		},
	})
	if string(data) != "complete data" || !errors.Is(err, closeFailure) {
		t.Fatalf("read result = %q, %v", data, err)
	}
	// Failure is recorded while the original operation token is still held.
	if err := scope.Wait(context.Background()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Close failure not sticky before release: %v", err)
	}
	release()
	<-scope.Done()
	if err := scope.Wait(context.Background()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("release erased Close failure: %v", err)
	}
}

func TestWriteFailureSurvivesSuccessfulRetry(t *testing.T) {
	scope := new(Scope)
	release, err := scope.Begin()
	if err != nil { t.Fatal(err) }
	writeFailure := errors.New("atomic helper: unclassified close or write error")
	if err := scope.RecordWriteError(writeFailure); err != writeFailure { t.Fatal(err) }
	release()
	retryRelease, err := scope.Begin()
	if err != nil { t.Fatal(err) }
	scope.RecordWriteError(nil)
	retryRelease()
	scope.Seal()
	for range 2 {
		if err := scope.Wait(context.Background()); !errors.Is(err, ErrIncomplete) {
			t.Fatalf("successful retry cleared original failure: %v", err)
		}
	}
}

func TestRejectedAdmissionAndCacheMissDoNotPoison(t *testing.T) {
	scope := new(Scope)
	release, err := scope.Begin()
	if err != nil { t.Fatal(err) }
	if _, err := scope.ReadFile(filepath.Join(t.TempDir(), "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing read = %v", err)
	}
	release()
	scope.Seal()
	if _, err := scope.Begin(); !errors.Is(err, ErrSealed) { t.Fatal(err) }
	if _, err := scope.ReadFile("never-opened"); !errors.Is(err, ErrSealed) { t.Fatal(err) }
	if _, err := scope.ReadDir("never-opened"); !errors.Is(err, ErrSealed) { t.Fatal(err) }
	if err := scope.Wait(context.Background()); err != nil {
		t.Fatalf("no-handle cache miss or no-IO rejection poisoned scope: %v", err)
	}
}
