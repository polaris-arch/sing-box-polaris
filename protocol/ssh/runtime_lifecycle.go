package ssh

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
)

func registerSSHCleanup(ctx context.Context, cleanup func() error) (bool, error) {
	return outbound.RegisterRuntimeCleanup(ctx, cleanup)
}

func (s *Outbound) initRuntime(ctx context.Context) {
	s.runtimeSource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	s.runtimeFences = outbound.NewRuntimeIOFenceSet()
	s.runtimeStop, s.runtimeCancel = context.WithCancel(context.Background())
	s.runtimeCleanup = outbound.OnceRuntimeCleanup(func() error {
		s.clientAccess.Lock()
		s.clientSealed = true
		s.clientAccess.Unlock()
		s.runtimeFences.Stop()
		s.runtimeCancel()
		// Creation slots include handshake cancellation callbacks and late
		// publication. Their raw fences are registered before SSH dispatch.
		err := s.runtimeFences.Wait()
		s.clientWatchers.Wait()
		return err
	})
}
