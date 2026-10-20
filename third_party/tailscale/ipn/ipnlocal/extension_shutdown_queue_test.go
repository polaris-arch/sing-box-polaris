// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/tailscale/util/execqueue"
)

type observedShutdownQueue struct {
	execqueue.ExecQueue
	entered chan struct{}
}
func (q *observedShutdownQueue) ShutdownAndWait(ctx context.Context) error {
	close(q.entered)
	return q.ExecQueue.ShutdownAndWait(ctx)
}

func TestExtensionHostShutdownJoinsStartedWork(t *testing.T) {
	q := &observedShutdownQueue{entered: make(chan struct{})}
	h := &ExtensionHost{workQueue: q, logf: t.Logf}
	workStarted := make(chan struct{})
	release := make(chan struct{})
	q.Add(func() {
		close(workStarted)
		<-release
		// The host mutex must remain available to executing callbacks.
		h.mu.Lock()
		h.mu.Unlock()
	})
	<-workStarted
	done := make(chan struct{})
	go func() { h.shutdownWorkQueue(); close(done) }()
	select {
	case <-q.entered:
	case <-done:
		close(release)
		t.Fatal("shutdown bypassed ShutdownAndWait")
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("shutdown failed to reach join")
	}
	select {
	case <-done:
		close(release)
		t.Fatal("shutdown returned while work remained")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not finish after work returned")
	}
}
