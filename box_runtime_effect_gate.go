package box

import (
	"context"
	"sync"
)

// runtimeEffectGate orders detached manual-control effects with publication.
// Its zero value is ready. A canceled publisher leaves no queued lock goroutine
// and holds no graph/coordinator guard while an earlier effect is completing.
type runtimeEffectGate struct {
	once  sync.Once
	token chan struct{}
}

func (g *runtimeEffectGate) initialize() {
	g.once.Do(func() { g.token = make(chan struct{}, 1); g.token <- struct{}{} })
}
func (g *runtimeEffectGate) Lock() { _ = g.LockContext(context.Background()) }
func (g *runtimeEffectGate) LockContext(ctx context.Context) error {
	g.initialize()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.token:
		if err := ctx.Err(); err != nil {
			g.Unlock()
			return err
		}
		return nil
	}
}
func (g *runtimeEffectGate) Unlock() { g.token <- struct{}{} }
