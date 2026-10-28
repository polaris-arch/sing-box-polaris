//go:build with_tailscale

package tailscale

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
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
	t.Run("TailcatInbound", func(t *testing.T) {
		router := &dnsContextRouter{t: t, wantLease: lease, wantValue: "packet"}
		handler := &TailcatInbound{ctx: legacy, router: router, logger: logger, node: &tailcatNode{}}
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
