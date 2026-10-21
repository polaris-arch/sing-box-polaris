package daemon

import (
	"context"

	"github.com/sagernet/sing-box/adapter"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type runtimeStartupOverridesKey struct{}

// runtimeSnapshot is a non-owning operational projection. It deliberately does
// not copy Instance's atomic/lifecycle ownership state. A current graph lease
// owns all endpoint pointers until the returned release function is called.
func (i *Instance) runtimeSnapshot() (*Instance, <-chan struct{}, func(), error) {
	release := func() {}
	if i == nil || i.instance == nil {
		return i, nil, release, nil
	}
	lease, changed, connected, err := i.instance.AcquireRuntimeAPI()
	if err != nil {
		return nil, changed, release, status.Error(codes.Unavailable, "runtime graph unavailable")
	}
	if !connected {
		return i, nil, release, nil
	}
	snapshot := &Instance{
		ctx:                   adapter.ContextWithRuntimeLease(i.ctx, lease),
		instance:              i.instance,
		connectionManager:     i.connectionManager,
		clashMode:             i.clashMode,
		trafficManager:        i.trafficManager,
		cacheFile:             i.cacheFile,
		pauseManager:          i.pauseManager,
		urlTestHistoryStorage: i.urlTestHistoryStorage,
		// Outbound wrappers retain their existing per-operation incarnation CAS.
		outboundManager:  i.outboundManager,
		endpointManager:  lease.View().EndpointManager(),
		logFactory:       i.logFactory,
		runtimeOverrides: i.runtimeOverrides,
	}
	return snapshot, changed, lease.Release, nil
}

func (s *StartedService) startedGraphInstance(ctx context.Context) (*Instance, func(), error) {
	instance, err := s.startedInstance(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	snapshot, _, release, err := instance.runtimeSnapshot()
	return snapshot, release, err
}

// Preserve request cancellation/metadata while lending the exact admitted graph
// to endpoint operations that fork resource continuations internally.
func (i *Instance) runtimeOperationContext(ctx context.Context) context.Context {
	if i != nil {
		if lease, ok := adapter.RuntimeLeaseFromContext(i.ctx); ok {
			return adapter.ContextWithRuntimeLease(ctx, lease)
		}
	}
	return ctx
}

// Inventory streams must wake on publication even when no URL-test or control
// event occurs. A closed same-epoch signal remains observable after Send.
func (s *StartedService) waitRuntimeAPIUpdate(ctx context.Context, graphChanged, history, historyDone <-chan struct{}, lifecycle <-chan *ServiceStatus, lifecycleDone <-chan struct{}) (bool, error) {
	select {
	case <-graphChanged:
	case <-history:
	case <-lifecycle:
	case <-ctx.Done():
		return true, ctx.Err()
	case <-s.ctx.Done():
		return true, s.ctx.Err()
	case <-historyDone:
		return true, nil
	case <-lifecycleDone:
		return true, nil
	}
	return false, nil
}
