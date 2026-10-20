package shadowtls

import (
	"context"
	"net"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func finishRuntimeConstruction(ctx context.Context, d *runtimeDialer) error {
	cleanup := outbound.OnceRuntimeCleanup(func() error { d.fences.Stop(); d.cancel(); return d.fences.Wait() })
	if err := ctx.Err(); err != nil { _ = cleanup(); return err }
	_, err := outbound.RegisterRuntimeCleanup(ctx, cleanup)
	return err
}

// ShadowTLS handshake callbacks and returned wrappers share these guarded
// physical carriers, including the default v3 standard-TLS callback. The original dialer is invoked synchronously under
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
