package mux

import (
	"context"
	"sync"
	"syscall"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-mux"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Client owns the raw graph-reaching boundaries of its pooled sessions. The
// underlying multiplexers may finish immutable-only tails after these fences
// close, but can no longer reach a retired dialer, TLS object or detour.
type Client struct {
	*mux.Client
	source adapter.RuntimeResourceSource
	stop context.Context
	cancel context.CancelFunc
	fences *outbound.RuntimeIOFenceSet
	cleanupOnce sync.Once
	cleanupErr error
}

func NewClientWithOptions(dialer N.Dialer, logger logger.Logger, options option.OutboundMultiplexOptions) (*Client, error) {
	return NewClientWithContext(context.Background(), dialer, logger, options)
}

func NewClientWithContext(ctx context.Context, dialer N.Dialer, logger logger.Logger, options option.OutboundMultiplexOptions) (*Client, error) {
	if !options.Enabled {
		return nil, nil
	}
	var brutalOptions mux.BrutalOptions
	if options.Brutal != nil && options.Brutal.Enabled {
		brutalOptions = mux.BrutalOptions{
			Enabled:    true,
			SendBPS:    uint64(options.Brutal.UpMbps * C.MbpsToBps),
			ReceiveBPS: uint64(options.Brutal.DownMbps * C.MbpsToBps),
		}
		if brutalOptions.SendBPS < mux.BrutalMinSpeedBPS {
			return nil, E.New("brutal: invalid upload speed")
		}
		if brutalOptions.ReceiveBPS < mux.BrutalMinSpeedBPS {
			return nil, E.New("brutal: invalid download speed")
		}
	}
	source, _ := adapter.RuntimeResourceSourceFromContext(ctx)
	stop, cancel := context.WithCancel(context.Background())
	client := &Client{source: source, stop: stop, cancel: cancel, fences: outbound.NewRuntimeIOFenceSet()}
	inner, err := mux.NewClient(mux.Options{
		Dialer:         &clientDialer{Dialer: dialer, owner: client},
		Logger:         logger,
		Protocol:       options.Protocol,
		MaxConnections: options.MaxConnections,
		MinStreams:     options.MinStreams,
		MaxStreams:     options.MaxStreams,
		Padding:        options.Padding,
		Brutal:         brutalOptions,
	})
	if err != nil { cancel(); return nil, err }
	client.Client = inner
	return client, nil
}

type clientDialer struct {
	N.Dialer
	owner *Client
}

func (d *clientDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx = adapter.ContextForMultiplexSession(ctx)
	if d.owner.source == nil { return d.Dialer.DialContext(ctx, network, destination) }
	creation, err := d.owner.fences.Begin()
	if err != nil { return nil, err }
	defer creation.Done()
	ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, d.owner.source)
	if err != nil { return nil, err }
	ctx, cancel := context.WithCancel(ctx)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(d.owner.stop, func() { defer close(callbackDone); cancel() })
	defer func() { if !stop() { <-callbackDone }; cancel() }()
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		if conn != nil { _, fence := outbound.WrapRuntimeOwnedConn(conn); d.owner.fences.Record(fence.RuntimeCloseAndWait()) }
		return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedConn(conn)
	if err := creation.Register(fence); err != nil { return nil, err }
	return &runtimeMuxConn{Conn: wrapped}, nil
}

func (d *clientDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx = adapter.ContextForMultiplexSession(ctx)
	if d.owner.source == nil { return d.Dialer.ListenPacket(ctx, destination) }
	creation, err := d.owner.fences.Begin()
	if err != nil { return nil, err }
	defer creation.Done()
	ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, d.owner.source)
	if err != nil { return nil, err }
	ctx, cancel := context.WithCancel(ctx)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(d.owner.stop, func() { defer close(callbackDone); cancel() })
	defer func() { if !stop() { <-callbackDone }; cancel() }()
	conn, err := d.Dialer.ListenPacket(ctx, destination)
	if err != nil {
		if conn != nil { _, fence := outbound.WrapRuntimeOwnedPacketConn(conn); d.owner.fences.Record(fence.RuntimeCloseAndWait()) }
		return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedPacketConn(conn)
	if err := creation.Register(fence); err != nil { return nil, err }
	return wrapped, nil
}

func (c *Client) RuntimeCloseAndWait() error {
	c.cleanupOnce.Do(func() {
		c.fences.Stop()
		c.cancel()
		// Boundary closes start before waiting for a pool's own mutex. A
		// creation that loses the seal race joins its late result itself.
		c.fences.Record(c.Client.Close())
		c.cleanupErr = c.fences.Wait()
	})
	return c.cleanupErr
}

// TCP Brutal requires syscall.Conn through encrypted protocol wrappers. This
// private physical-session adapter exposes only descriptor callbacks guarded
// by the already-registered owned carrier, never an unwrapped connection.
type runtimeMuxConn struct { net.Conn }
func (c *runtimeMuxConn) SyscallConn() (syscall.RawConn, error) {
	return outbound.RuntimeSyscallConn(c.Conn)
}
