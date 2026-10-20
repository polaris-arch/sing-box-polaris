package snell

import (
	"context"
	"net"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
)

func (h *Outbound) initRuntimeCleanup(ctx context.Context) error {
	h.runtimeContext = ctx
	h.runtimeSource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	h.runtimeCleanup = outbound.OnceRuntimeCleanup(h.closeRuntimeResources)
	return nil
}

func (h *Outbound) finishRuntimeConstruction(ctx context.Context) error {
	var err error
	h.constructionCleanup, err = outbound.RegisterRuntimeCleanup(ctx, h.runtimeCleanup)
	return err
}

func (h *Outbound) registerRuntimeStart(scope *adapter.Scope) error {
	if err := scope.Context().Err(); err != nil {
		_ = h.runtimeCleanup()
		return err
	}
	if h.constructionCleanup { return nil }
	ctx := adapter.ContextWithConstructionScope(scope.Context(), scope)
	var err error
	h.constructionCleanup, err = outbound.RegisterRuntimeCleanup(ctx, h.runtimeCleanup)
	return err
}

func (h *Outbound) closeRuntimeResources() error {
	if h.runtimeDialer == nil { return nil }
	h.runtimeDialer.fences.Stop()
	h.runtimeDialer.cancel()
	if h.client != nil { h.runtimeDialer.fences.Record(h.client.Close()) }
	return h.runtimeDialer.fences.Wait()
}

// Reuse expiration/drain workers only retain protocol-private state and these
// guarded physical carriers. The original dialer is invoked synchronously under
// an exact owner continuation, never stored with a borrowed operation context.
type runtimeDialer struct {
	N.Dialer
	source adapter.RuntimeResourceSource
	fences *outbound.RuntimeIOFenceSet
	stop context.Context
	cancel context.CancelFunc
}
func newRuntimeDialer(ctx context.Context, dialer N.Dialer) *runtimeDialer {
	source, _ := adapter.RuntimeResourceSourceFromContext(ctx)
	stop, cancel := context.WithCancel(context.Background())
	return &runtimeDialer{Dialer: dialer, source: source, fences: outbound.NewRuntimeIOFenceSet(), stop: stop, cancel: cancel}
}
func (d *runtimeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d.source == nil { return d.Dialer.DialContext(ctx, network, destination) }
	creation, err := d.fences.Begin()
	if err != nil { return nil, err }; defer creation.Done()
	ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, d.source)
	if err != nil { return nil, err }
	ctx, cancel := context.WithCancel(ctx)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(d.stop, func() { defer close(callbackDone); cancel() })
	defer func() { if !stop() { <-callbackDone }; cancel() }()
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		if conn != nil { _, fence := outbound.WrapRuntimeOwnedConn(conn); d.fences.Record(fence.RuntimeCloseAndWait()) }
		return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedConn(conn)
	if err := creation.Register(fence); err != nil { return nil, err }
	return wrapped, nil
}
