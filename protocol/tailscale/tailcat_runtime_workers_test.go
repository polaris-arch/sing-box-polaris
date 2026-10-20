//go:build with_tailscale

package tailscale

import (
 "context"
 "testing"
 "time"
)

func TestTailcatOriginalWorkerCompletion(t *testing.T) {
 ctx, cancel := context.WithCancel(context.Background())
 node := &tailcatNode{ctx: ctx, cancel: cancel}
 entered, release := make(chan struct{}), make(chan struct{})
 if !node.startWorker(func() { close(entered); <-release }) { t.Fatal("initial worker rejected") }
 <-entered
 done := make(chan struct{})
 go func() { node.stopWorkers(); close(done) }()
 <-ctx.Done() // cancellation follows admission sealing, not worker completion
 if node.startWorker(func() { t.Error("late callback ran") }) { t.Fatal("late worker admitted") }
 select { case <-done: t.Fatal("active original worker declared complete"); default: }
 close(release)
 select { case <-done: case <-time.After(time.Second): t.Fatal("original worker was not joined") }
 node.stopWorkers()
}
