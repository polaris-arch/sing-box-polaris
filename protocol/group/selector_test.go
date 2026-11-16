package group

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
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
	closed bool
}

func (c *selectorTrackedConn) Close() error {
	c.closed = true
	return nil
}

type selectorTrackedPacketConn struct {
	net.PacketConn
	closed bool
}

func (c *selectorTrackedPacketConn) Close() error {
	c.closed = true
	return nil
}

func TestSelectorLateDialAfterSwitch(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		for _, tc := range []struct {
			name              string
			external          bool
			interruptExternal bool
			switchNode        bool
			wantClosed        bool
		}{
			{name: "internal", switchNode: true, wantClosed: true},
			{name: "external-preserved", external: true, switchNode: true},
			{name: "external-interrupted", external: true, interruptExternal: true, switchNode: true, wantClosed: true},
			{name: "unchanged"},
		} {
			t.Run(network+"/"+tc.name, func(t *testing.T) {
				stream := &selectorTrackedConn{}
				packet := &selectorTrackedPacketConn{}
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
				}
				s.selected.Store(old)
				ctx := context.Background()
				if tc.external {
					ctx = interrupt.ContextWithIsExternalConnection(ctx)
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
				if tc.wantClosed {
					if !errors.Is(err, net.ErrClosed) || !closed {
						t.Fatalf("old dial survived switch: err=%v closed=%v", err, closed)
					}
				} else if err != nil || closed {
					t.Fatalf("valid dial interrupted: err=%v closed=%v", err, closed)
				}
			})
		}
	}
}
