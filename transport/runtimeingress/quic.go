//go:build with_quic

package runtimeingress

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
)

type (
	quicAcceptor interface {
		Accept(context.Context) (*quic.Conn, error)
		Close() error
		Addr() net.Addr
	}
	QUICEndpoint struct {
		acceptor  quicAcceptor
		transport *quic.Transport
		packet    *outbound.RuntimeIOFence
		callbacks *outbound.RuntimeIOFence
	}
)

// ListenQUIC uses the pinned transport's handshake-before-admission hook. A
// private packet queue is installed before physical listener staging. Session
// lineage is acquired exactly once at connection creation, never per stream.
type QUICTransportOptions struct {
	StatelessReset                   bool
	DisableVersionNegotiationPackets bool
	StatelessResetKey                *quic.StatelessResetKey
}

func ListenQUIC(ctx context.Context, ingress *listener.Listener, config tls.ServerConfig, options *quic.Config, early bool) (*QUICEndpoint, error) {
	packet, err := ingress.PrepareRuntimePacketTransport()
	if err != nil {
		return nil, err
	}
	return ListenQUICPacket(ctx, ingress, packet, config, options, early, QUICTransportOptions{})
}

// ListenQUICPacket preserves the caller's protocol obfuscation wrapper. The
// supplied packet must wrap this ingress's private endpoint, not an independently
// opened socket; the caller retains no competing reader or transport owner.
func ListenQUICPacket(ctx context.Context, ingress *listener.Listener, packet net.PacketConn, config tls.ServerConfig, options *quic.Config, early bool, transportOptions QUICTransportOptions) (*QUICEndpoint, error) {
	if ingress == nil || packet == nil {
		return nil, errors.New("missing private QUIC ingress packet endpoint")
	}
	if config == nil {
		return nil, errors.New("QUIC requires TLS server configuration")
	}

	if err := tls.ValidateRuntimeServer(config); err != nil {
		return nil, err
	}
	standard, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	candidate := &quic.Config{}
	if options != nil {
		candidate = options.Clone()
	}
	if candidate.HandshakeIdleTimeout == 0 {
		candidate.HandshakeIdleTimeout = config.HandshakeTimeout()
	}
	guarded, packetFence := outbound.WrapRuntimeOwnedPacketConn(packet)
	endpoint := &QUICEndpoint{packet: packetFence}
	native := &quic.Transport{Conn: &quicPacketAddressView{PacketConn: guarded, address: ingress.RuntimePacketLocalAddr}, DisableVersionNegotiationPackets: transportOptions.DisableVersionNegotiationPackets}
	if transportOptions.StatelessResetKey != nil {
		key := *transportOptions.StatelessResetKey
		native.StatelessResetKey = &key
	} else if transportOptions.StatelessReset {
		var key quic.StatelessResetKey
		if _, err := rand.Read(key[:]); err != nil {
			return nil, errors.Join(err, packetFence.RuntimeCloseAndWait())
		}
		native.StatelessResetKey = &key
	}
	endpoint.transport = native
	endpoint.callbacks = outbound.NewRuntimeIOFence(func() error {
		// Transport.Close interrupts and joins its packet reader; the private packet
		// fence then joins actual I/O methods. No native socket ownership is stolen.
		err := native.Close()
		err = errors.Join(err, packetFence.RuntimeCloseAndWait())
		if err != nil {
			return fmt.Errorf("QUIC endpoint cleanup incomplete: %v", err)
		}
		return nil
	})
	native.ConnContext = func(connection context.Context, _ *quic.ClientInfo) (context.Context, error) {
		leave, err := endpoint.callbacks.Acquire()
		if err != nil {
			return nil, err
		}
		defer leave()
		// The pinned library cancels this context on both handshake failure and
		// connection termination. The callback touches only owned lease release.
		return BindSession(connection, ingress.AcquireRuntimeSession)
	}
	if early {
		endpoint.acceptor, err = native.ListenEarly(standard, candidate)
	} else {
		endpoint.acceptor, err = native.Listen(standard, candidate)
	}
	if err != nil {
		return nil, errors.Join(err, endpoint.Close())
	}
	// Runtime lifetime is independent of the preparation RPC. Final Box/candidate
	// cancellation interrupts physical sessions even while they still own leases.
	context.AfterFunc(ctx, func() { _ = endpoint.Close() })
	if err = adapter.DeferConstructionCleanup(ctx, endpoint.RuntimeCloseAndWait); err != nil {
		return nil, err
	}
	if err = adapter.ConstructionScopeErr(ctx); err != nil {
		return nil, err
	}
	return endpoint, nil
}
func (e *QUICEndpoint) Accept(ctx context.Context) (*quic.Conn, error) { return e.acceptor.Accept(ctx) }
func (e *QUICEndpoint) Addr() net.Addr                                 { return e.acceptor.Addr() }
func (e *QUICEndpoint) Close() error                                   { return e.callbacks.RuntimeCloseAndWait() }
func (e *QUICEndpoint) RuntimeCloseAndWait() error                     { return e.Close() }

// Keep guarded I/O and close ownership intact while allowing port-zero binding
// to supply the actual address before quic-go snapshots its first session.
// This facade has no syscall/OOB/Upstream escape to the underlying socket.
type quicPacketAddressView struct {
	net.PacketConn
	address func() net.Addr
}

func (p *quicPacketAddressView) LocalAddr() net.Addr { return p.address() }
