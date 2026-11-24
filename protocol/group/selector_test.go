package group

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type selectorDelayedOutbound struct {
	adapter.Outbound
	entered chan struct{}
	release chan struct{}
	stream  net.Conn
	packet  net.PacketConn
}

func (o *selectorDelayedOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	close(o.entered)
	<-o.release
	return o.stream, nil
}

func (o *selectorDelayedOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	close(o.entered)
	<-o.release
	return o.packet, nil
}

type selectorTrackedConn struct {
	net.Conn
	closed   bool
	closeErr error
}

func (c *selectorTrackedConn) Close() error {
	if c.closed {
		return net.ErrClosed
	}
	c.closed = true
	return c.closeErr
}

type selectorTrackedPacketConn struct {
	net.PacketConn
	closed   bool
	closeErr error
}

func (c *selectorTrackedPacketConn) Close() error {
	if c.closed {
		return net.ErrClosed
	}
	c.closed = true
	return c.closeErr
}

func TestSelectorLateDialAfterSwitch(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		for _, tc := range []struct {
			name              string
			external          bool
			interruptExternal bool
			switchNode        bool
			wantClosed        bool
			scoped            bool
			registered        bool
			closeErr          error
		}{
			{name: "internal", switchNode: true, wantClosed: true},
			{name: "external-preserved", external: true, switchNode: true},
			{name: "external-interrupted", external: true, interruptExternal: true, switchNode: true, wantClosed: true},
			{name: "scoped-probe", external: true, switchNode: true, wantClosed: true, scoped: true},
			{name: "unchanged"},
			{name: "registered-interrupted", switchNode: true, registered: true, closeErr: errors.New("interrupted carrier close failed")},
		} {
			if tc.scoped && network != N.NetworkTCP {
				continue
			}
			t.Run(network+"/"+tc.name, func(t *testing.T) {
				stream := &selectorTrackedConn{closeErr: tc.closeErr}
				packet := &selectorTrackedPacketConn{closeErr: tc.closeErr}
				old := &selectorDelayedOutbound{
					entered: make(chan struct{}), release: make(chan struct{}),
					stream: stream, packet: packet,
				}
				var release sync.Once
				t.Cleanup(func() { release.Do(func() { close(old.release) }) })
				s := &Selector{
					ctx:                          context.Background(),
					outbounds:                    map[string]adapter.Outbound{"new": &selectorDelayedOutbound{}},
					interruptGroup:               interrupt.NewGroup(),
					interruptExternalConnections: tc.interruptExternal,
					ephemeralPoolProbe:           tc.scoped,
				}
				s.selected.Store(&selectorSelection{outbound: old})
				ctx := context.Background()
				if tc.external {
					ctx = interrupt.ContextWithIsExternalConnection(ctx)
				}
				wantErr := error(net.ErrClosed)
				if tc.scoped {
					pipe, peer := net.Pipe()
					t.Cleanup(func() { _ = pipe.Close(); _ = peer.Close() })
					stream.Conn = pipe
					stream.closeErr = errors.New("scoped carrier close failed")
					old.stream, _ = outbound.WrapRuntimeOwnedConn(stream)
					ctx, _, _ = s.ScopePoolProbeSelection(ctx, 1)
					wantErr = urltest.ErrProbeNotRun
				}
				var conn io.Closer
				var err error
				done := make(chan struct{})
				go func() {
					defer close(done)
					if network == N.NetworkTCP {
						conn, err = s.DialContext(ctx, network, M.Socksaddr{})
					} else {
						conn, err = s.ListenPacket(ctx, M.Socksaddr{})
					}
				}()
				awaitEpochSignal(t, old.entered)
				if tc.registered {
					release.Do(func() { close(old.release) })
					awaitEpochSignal(t, done)
				}
				if tc.switchNode && !s.SelectOutbound("new") {
					t.Fatal("selection rejected")
				}
				// Complete the old dial only after selection and interruption finish.
				release.Do(func() { close(old.release) })
				awaitEpochSignal(t, done)
				closed := stream.closed || packet.closed
				if conn != nil && err == nil {
					t.Cleanup(func() { conn.Close() })
				}
				if tc.registered {
					// The interrupted carrier's first close result reaches its owner.
					if err != nil || !closed {
						t.Fatalf("registered dial was not interrupted: err=%v closed=%v", err, closed)
					}
					if got := conn.Close(); got != tc.closeErr {
						t.Fatalf("owner close after interrupt = %v, want first result %v", got, tc.closeErr)
					}
				} else if tc.wantClosed {
					if !errors.Is(err, wantErr) || !closed || (tc.scoped && !errors.Is(err, stream.closeErr)) {
						t.Fatalf("old dial survived switch: err=%v closed=%v", err, closed)
					}
				} else if err != nil || closed {
					t.Fatalf("valid dial interrupted: err=%v closed=%v", err, closed)
				}
			})
		}
	}
}
