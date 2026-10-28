package tuic

import (
 "context"
 "sync/atomic"
 "testing"
)

func TestPacketWriteCancellationJoinsRunningCallback(t *testing.T) {
 ctx, cancel := context.WithCancel(context.Background())
 defer cancel()
 entered, release := make(chan struct{}), make(chan struct{})
 var returned atomic.Bool
 stop := watchPacketWriteCancellation(ctx, func() {
  close(entered)
  <-release
  returned.Store(true)
 })
 cancel()
 <-entered
 stopped := make(chan struct{})
 go func() { stop(); close(stopped) }()
 select {
 case <-stopped: t.Fatal("stop returned before cancellation callback")
 default:
 }
 close(release)
 <-stopped
 if !returned.Load() { t.Fatal("callback completion was not joined") }
}

func TestPacketWriteCancellationStopBeforeCancel(t *testing.T) {
 ctx, cancel := context.WithCancel(context.Background())
 defer cancel()
 var called atomic.Bool
 stop := watchPacketWriteCancellation(ctx, func() { called.Store(true) })
 stop()
 cancel()
 if called.Load() { t.Fatal("stopped callback ran") }
}
