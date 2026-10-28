package tfo

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type runtimeBlockingDeadline struct {
	entered chan struct{}
	release chan struct{}
	once sync.Once
}

func (c *runtimeBlockingDeadline) SetWriteDeadline(time.Time) error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return nil
}

func TestRuntimeWriteCancellationJoinsActualDeadlineMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &runtimeBlockingDeadline{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(c.release) }) }
	t.Cleanup(release)
	done := make(chan error, 1)
	go func() {
		done <- connWriteFunc(ctx, c, func(*runtimeBlockingDeadline) error {
			cancel()
			<-c.entered
			return nil
		})
	}()
	select { case <-c.entered: case <-time.After(5*time.Second): t.Fatal("deadline callback did not enter") }
	select { case err := <-done: t.Fatalf("returned before deadline mutation completed: %v", err); default: }
	release()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) { t.Fatalf("lost cancellation: %v", err) }
	case <-time.After(5*time.Second):
		t.Fatal("deadline join did not complete")
	}
}

func TestRuntimeWriteWithoutCancellationDoesNotWaitForCallback(t *testing.T) {
	c := &runtimeBlockingDeadline{entered: make(chan struct{}), release: make(chan struct{})}
	defer close(c.release)
	if err := connWriteFunc(context.Background(), c, func(*runtimeBlockingDeadline) error { return nil }); err != nil { t.Fatal(err) }
	select { case <-c.entered: t.Fatal("uncanceled write ran callback"); default: }
}
