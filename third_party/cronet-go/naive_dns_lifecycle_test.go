package cronet

import (
 "context"
 "sync/atomic"
 "testing"
)

func TestNaiveDNSCancellationJoinsClose(t *testing.T) {
 ctx, cancel := context.WithCancel(context.Background())
 defer cancel()
 entered, release := make(chan struct{}), make(chan struct{})
 var returned atomic.Bool
 stop := watchNaiveDNSCancellation(ctx, func() error {
  close(entered); <-release; returned.Store(true); return nil
 })
 cancel(); <-entered
 stopped := make(chan struct{})
 go func() { stop(); close(stopped) }()
 select { case <-stopped: t.Fatal("watcher returned before close"); default: }
 close(release); <-stopped
 if !returned.Load() { t.Fatal("close was not joined") }
}
func TestNaiveDNSCancellationCanStopBeforeCancel(t *testing.T) {
 ctx, cancel := context.WithCancel(context.Background())
 defer cancel()
 var called atomic.Bool
 stop := watchNaiveDNSCancellation(ctx, func() error { called.Store(true); return nil })
 stop(); cancel()
 if called.Load() { t.Fatal("stopped watcher closed socket") }
}
