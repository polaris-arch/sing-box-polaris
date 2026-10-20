package proxybridge

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
)

// The manager never sees an owner continuation: it calls this synchronous
// boundary with the sanitized owner-lifetime context, then dispatches copy
// workers using only fenced carriers and its existing callback boundary.
type ownedDialer struct { bridge *Bridge }
func (d *ownedDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	b := d.bridge
	creation, err := b.fences.Begin(); if err != nil { return nil, err }; defer creation.Done()
	owned, release, err := b.acquireRuntime(ctx)
	if err != nil { return nil, err }
	if b.runtimeSource != nil {
		owned, err = outbound.ContextForRuntimeOwnedSession(owned, b.runtimeSource)
		if err != nil { release(); return nil, err }
	}
	conn, err := b.dialer.DialContext(owned, network, destination)
	if err != nil {
		if conn != nil { _, fence := outbound.WrapRuntimeOwnedConn(conn); b.fences.Record(fence.RuntimeCloseAndWait()) }
		release(); return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedConn(conn)
	err = creation.Register(fence)
	release()
	if err != nil { return nil, err }
	return wrapped, nil
}
func (d *ownedDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	b := d.bridge
	creation, err := b.fences.Begin(); if err != nil { return nil, err }; defer creation.Done()
	owned, release, err := b.acquireRuntime(ctx)
	if err != nil { return nil, err }
	if b.runtimeSource != nil {
		owned, err = outbound.ContextForRuntimeOwnedSession(owned, b.runtimeSource)
		if err != nil { release(); return nil, err }
	}
	conn, err := b.dialer.ListenPacket(owned, destination)
	if err != nil {
		if conn != nil { _, fence := outbound.WrapRuntimeOwnedPacketConn(conn); b.fences.Record(fence.RuntimeCloseAndWait()) }
		release(); return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedPacketConn(conn)
	err = creation.Register(fence)
	release()
	if err != nil { return nil, err }
	return wrapped, nil
}
