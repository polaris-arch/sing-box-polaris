package direct

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

type pingTestNetwork struct{ adapter.NetworkManager }

func (pingTestNetwork) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}

func (pingTestNetwork) DefaultOptions() adapter.NetworkOptions        { return adapter.NetworkOptions{} }
func (pingTestNetwork) AutoDetectInterface() bool                     { return false }
func (pingTestNetwork) AutoRedirectOutputMarkFunc() control.Func      { return nil }
func (pingTestNetwork) InterfaceMonitor() tun.DefaultInterfaceMonitor { return nil }

type pingTestDNS struct{ adapter.DNSTransportManager }

func (pingTestDNS) Transports() []adapter.DNSTransport { return nil }
func (pingTestDNS) Default() adapter.DNSTransport      { return nil }

type pingTestReturn struct{}

func (*pingTestReturn) ReturnHeadroom() int                     { return 0 }
func (*pingTestReturn) ReturnPackets(packets [][]byte) [][]byte { return packets }

func pingConstructorContext(ctx context.Context) context.Context {
	ctx = service.ContextWith[adapter.NetworkManager](ctx, pingTestNetwork{})
	return service.ContextWith[adapter.DNSTransportManager](ctx, pingTestDNS{})
}

func newPingTestOutbound(t *testing.T, ctx context.Context) *Outbound {
	t.Helper()
	value, err := NewOutbound(pingConstructorContext(ctx), nil, log.NewNOPFactory().Logger(), "direct-test", option.DirectOutboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := value.(*Outbound)
	if h.icmpPort == nil {
		t.Fatal("production direct constructor did not wire its ICMP port")
	}
	return h
}

func TestDirectConstructorOwnsTerminalPingCleanupBeforeStart(t *testing.T) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	ctx := adapter.ContextWithConstructionScope(scope.Context(), scope)
	h := newPingTestOutbound(t, ctx)
	if !h.constructionCleanup {
		t.Fatal("constructor left cleanup for Start")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.AttachReturn(&pingTestReturn{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("constructor cleanup only reset the port: %v", err)
	}
	if err := h.icmpPort.Wait(context.Background()); err != nil {
		t.Fatalf("terminal constructor cleanup did not finish: %v", err)
	}
}

func TestDirectInterfaceUpdatedResetsButScopeCloseSealsPing(t *testing.T) {
	h := newPingTestOutbound(t, context.Background())
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err := h.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	h.InterfaceUpdated(context.Background())
	returnPath := &pingTestReturn{}
	if err := h.AttachReturn(returnPath); err != nil {
		t.Fatalf("network change permanently sealed the port: %v", err)
	}
	if err := h.DetachReturn(returnPath); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.AttachReturn(returnPath); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Start registered reset instead of terminal close: %v", err)
	}
}

func TestDirectLateStartCleansPingImmediately(t *testing.T) {
	h := newPingTestOutbound(t, context.Background())
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Start(adapter.StartStateInitialize, scope); !errors.Is(err, context.Canceled) {
		t.Fatalf("late Start = %v", err)
	}
	if err := h.AttachReturn(&pingTestReturn{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Scope.Add stranded the late port: %v", err)
	}
}

func TestDirectCanceledConstructionClosesAlreadyAcquiredPing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	ctx = adapter.ContextWithConstructionScope(scope.Context(), scope)
	h := &Outbound{icmpPort: ping.NewPort(ctx, logger.NOP(), nil, 0)}
	cancel()
	if err := h.registerICMPCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled registration = %v", err)
	}
	if err := h.icmpPort.AttachReturn(&pingTestReturn{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("partial constructor left its acquired port live: %v", err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectClosedScopeOnLiveContextCannotPublishSealedPort(t *testing.T) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	// DeferConstructionCleanup checks the scope's context, even when this
	// wrapping constructor context is itself still live.
	ctx := adapter.ContextWithConstructionScope(context.Background(), scope)
	value, err := NewOutbound(pingConstructorContext(ctx), nil, log.NewNOPFactory().Logger(), "closed-scope", option.DirectOutboundOptions{})
	if !errors.Is(err, os.ErrClosed) || value != nil {
		t.Fatalf("published outbound after immediate cleanup: %v, %v", value, err)
	}
}
