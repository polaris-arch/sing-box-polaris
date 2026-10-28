// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"testing"
	"time"
)

// This regression exercises Auto.Shutdown itself, not just ExecQueue.
// No network or real state directory is needed.
func TestAutoShutdownWaitsForStartedObserver(t *testing.T) {
	finished := make(chan struct{})
	close(finished)
	shutdownEntered := make(chan struct{})
	c := &Auto{
		logf: t.Logf,
		authDone: finished,
		mapDone: finished,
		updateDone: finished,
		shutdownFn: func() { close(shutdownEntered) },
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	c.observerQueue.Add(func() {
		close(entered)
		<-release
		// Shutdown must not hold the Auto mutex while joining its observer.
		c.mu.Lock()
		c.mu.Unlock()
	})
	<-entered
	done := make(chan struct{})
	go func() { c.Shutdown(); close(done) }()
	<-shutdownEntered
	select {
	case <-done:
		close(release)
		t.Fatal("Shutdown returned with the observer still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown failed to join released observer")
	}
}
