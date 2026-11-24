package wireguard

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type (
	dnsContextKey    struct{}
	dnsBorrowedLease struct{ adapter.RuntimeLease }
)

func (*dnsBorrowedLease) Fork() (adapter.RuntimeLease, error) {
	panic("wrapper must not fork the route-owned async admission")
}
func (*dnsBorrowedLease) Release() { panic("wrapper must not release borrowed admission") }

type dnsContextRouter struct {
	adapter.Router
	t         *testing.T
	wantLease adapter.RuntimeLease
	wantValue string
	calls     int
}

func (r *dnsContextRouter) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	r.calls++
	if ctx.Value(dnsContextKey{}) != r.wantValue {
		r.t.Fatal("wrapper replaced the received context")
	}
	lease, ok := adapter.RuntimeLeaseFromContext(ctx)
	if !ok || lease != r.wantLease {
		r.t.Fatal("wrapper lost or replaced packet admission")
	}
	if string(payload) != "query" || metadata.Source.Port != 10000 || metadata.Destination.Port != 53 {
		r.t.Fatal("DNS payload or metadata changed")
	}
}

func TestDNSPacketExPreservesBorrowedAdmission(t *testing.T) {
	lease := &dnsBorrowedLease{}
	legacy := adapter.ContextWithRuntimeLease(context.WithValue(context.Background(), dnsContextKey{}, "legacy"), lease)
	incoming := adapter.ContextWithRuntimeLease(context.WithValue(context.Background(), dnsContextKey{}, "packet"), lease)
	logger := log.NewNOPFactory().Logger()
	source := M.ParseSocksaddr("192.0.2.1:10000")
	destination := M.ParseSocksaddr("192.0.2.2:53")
	t.Run("Endpoint", func(t *testing.T) {
		router := &dnsContextRouter{t: t, wantLease: lease, wantValue: "packet"}
		handler := &Endpoint{ctx: legacy, router: router, logger: logger}
		var ex tun.DNSPacketHandlerEx = handler
		ex.NewDNSPacketEx(incoming, []byte("query"), source, destination, nil)
		if router.calls != 1 {
			t.Fatal("Ex forwarding did not finish synchronously")
		}
		router.wantValue = "legacy"
		handler.NewDNSPacket([]byte("query"), source, destination, nil)
		if router.calls != 2 {
			t.Fatal("legacy method did not delegate")
		}
	})
}

type pendingInboundPacketClose struct {
	net.Conn
	started, finish chan struct{}
	err             error
}

func (c *pendingInboundPacketClose) Close() error {
	close(c.started)
	<-c.finish
	_ = c.Conn.Close()
	return c.err
}

func TestRuntimeInboundPacketPreservesCloseCompletion(t *testing.T) {
	for name, closeErr := range map[string]error{"success": nil, "failure": errors.New("packet close failed")} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			raw, peer := net.Pipe()
			defer peer.Close()
			barrier := &pendingInboundPacketClose{Conn: raw, started: make(chan struct{}), finish: make(chan struct{}), err: closeErr}
			owned, packet, _, err := (&runtimeEndpointPhysical{}).wrapInboundPacket(ctx, bufio.NewPacketConn(bufio.NewUnbindPacketConn(barrier)), nil)
			if err != nil {
				t.Fatal(err)
			}
			first := make(chan error, 1)
			go func() { first <- packet.Close() }()
			defer func() {
				close(barrier.finish)
				<-first
			}()
			select {
			case <-barrier.started:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err = packet.Close(); err != outbound.ErrRuntimeClosePending {
				t.Fatalf("concurrent close returned %v, want pending", err)
			}
			wait, ok := outbound.RuntimeInboundCloseFromContext(owned)
			if !ok {
				t.Fatal("packet wrapper hid the exact close completion")
			}
			// Release the original close before observing its terminal result.
			barrier.finish <- struct{}{}
			result := make(chan error, 1)
			go func() { result <- wait() }()
			select {
			case err = <-result:
				if !errors.Is(err, closeErr) {
					t.Fatalf("joined close returned %v, want %v", err, closeErr)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
