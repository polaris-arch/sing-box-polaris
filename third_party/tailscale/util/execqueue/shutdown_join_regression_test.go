// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package execqueue

import (
	"context"
	"testing"
)

// Documents why Shutdown followed by Wait is not a drain proof in this pin.
func TestClosedQueueWaitIsNotJoin(t *testing.T) {
	var q ExecQueue
	started := make(chan struct{})
	release := make(chan struct{})
	q.Add(func() { close(started); <-release })
	<-started
	q.Shutdown()
	if err := q.Wait(context.Background()); err == nil {
		close(release)
		t.Fatal("expected closed-queue error from Wait")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := q.ShutdownAndWait(ctx); err != context.Canceled {
		close(release)
		t.Fatalf("in-flight callback must not be reported drained: %v", err)
	}
	close(release)
	if err := q.ShutdownAndWait(context.Background()); err != nil {
		t.Fatal(err)
	}
}
