package shadowtls

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type handoffServiceFixture func(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) error

func (f handoffServiceFixture) NewConnection(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) error {
	return f(ctx, conn, source, destination, onClose)
}

type handoffRouterFixture struct {
	adapter.Router
	finish N.CloseHandlerFunc
	invoke func(net.Conn, N.CloseHandlerFunc)
}

func (r *handoffRouterFixture) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, finish N.CloseHandlerFunc) {
	r.finish = finish
	if r.invoke != nil {
		r.invoke(conn, finish)
	}
}

func newHandoffInbound(router adapter.Router) *Inbound {
	logger := log.NewNOPFactory().Logger()
	return &Inbound{router: router, logger: logger, listener: listener.New(listener.Options{Context: context.Background(), Logger: logger})}
}

func TestShadowTLSHandoffAndSynchronousFallbackHaveSeparateOwnership(t *testing.T) {
	for _, mode := range []string{"fallback-success", "fallback-failure", "async-success", "async-failure", "handler-completed", "handler-and-service-failure", "handler-admission-rejected", "nil-callback"} {
		t.Run(mode, func(t *testing.T) {
			router := new(handoffRouterFixture)
			h := newHandoffInbound(router)
			raw := new(handshakeConnFixture)
			releases := 0
			owned := outbound.WrapRuntimeConn(context.Background(), func() { releases++ }, raw)
			defer owned.Close()
			serviceErr, routeErr := errors.New("service error after handshake"), errors.New("route rejected")
			if mode == "handler-completed" {
				router.invoke = func(_ net.Conn, finish N.CloseHandlerFunc) { finish(nil) }
			}
			if mode == "handler-and-service-failure" {
				router.invoke = func(conn net.Conn, finish N.CloseHandlerFunc) { N.CloseOnHandshakeFailure(conn, finish, routeErr) }
			}
			if mode == "handler-admission-rejected" {
				h.runtime = &inboundRuntime{callbacks: outbound.NewRuntimeIOFence(func() error { return nil })}
			}
			h.service = handoffServiceFixture(func(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) error {
				switch mode {
				case "fallback-success":
					return nil
				case "fallback-failure":
					return serviceErr
				case "handler-admission-rejected":
					_ = h.runtime.callbacks.Close()
				}
				(*inboundHandler)(h).NewConnectionEx(ctx, conn, source, destination, onClose)
				if mode == "async-failure" || mode == "handler-and-service-failure" {
					return serviceErr
				}
				return nil
			})
			terminals := 0
			var reported error
			var callback N.CloseHandlerFunc = func(err error) { terminals++; reported = err; _ = owned.Close() }
			if mode == "nil-callback" {
				callback = nil
			}
			h.NewConnection(context.Background(), owned, adapter.InboundContext{}, callback)
			if mode == "async-success" || mode == "nil-callback" {
				if terminals != 0 || releases != 0 || raw.closes != 0 {
					t.Fatal("handoff closed before terminal completion")
				}
				if mode == "async-success" {
					router.finish(nil)
				}
			} else if terminals != 1 || releases != 1 || raw.closes != 1 {
				t.Fatalf("terminal ownership mismatch: callback=%d release=%d physical-close=%d", terminals, releases, raw.closes)
			}
			if mode == "fallback-failure" || mode == "async-failure" {
				if !errors.Is(reported, serviceErr) {
					t.Fatal("service failure lost")
				}
			}
			if mode == "handler-and-service-failure" && !errors.Is(reported, routeErr) {
				t.Fatal("first terminal failure overwritten by outer callback")
			}
			if mode == "handler-admission-rejected" {
				if reported == nil || router.finish != nil {
					t.Fatal("rejected handler reached route or lost error")
				}
				if err := h.runtime.callbacks.RuntimeCloseAndWait(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestShadowTLSHandoffMarkerIsPerConnection(t *testing.T) {
	router := new(handoffRouterFixture)
	h := newHandoffInbound(router)
	requests := 0
	h.service = handoffServiceFixture(func(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) error {
		requests++
		if requests == 1 {
			(*inboundHandler)(h).NewConnectionEx(ctx, conn, source, destination, onClose)
		}
		return nil
	})
	first, second := new(handshakeConnFixture), new(handshakeConnFixture)
	firstTerminals, secondTerminals := 0, 0
	h.NewConnection(context.Background(), first, adapter.InboundContext{}, func(error) { firstTerminals++; _ = first.Close() })
	h.NewConnection(context.Background(), second, adapter.InboundContext{}, func(error) { secondTerminals++; _ = second.Close() })
	if firstTerminals != 0 || secondTerminals != 1 || first.closes != 0 || second.closes != 1 {
		t.Fatal("one connection's handoff changed another connection's fallback lifetime")
	}
	router.finish(nil)
	if firstTerminals != 1 || first.closes != 1 {
		t.Fatal("first terminal callback lost")
	}
}

func TestNilHandshakeResultRemainsTerminalForSynchronousCallers(t *testing.T) {
	// Legacy Shadowsocks and synchronous DNS hijack callers intentionally rely
	// on this helper contract. Fix the asynchronous call sites, not the helper.
	conn := new(handshakeConnFixture)
	terminals := 0
	N.CloseOnHandshakeFailure(conn, func(err error) {
		if err != nil {
			t.Fatal(err)
		}
		terminals++
		_ = conn.Close()
	}, nil)
	if terminals != 1 || conn.closes != 1 {
		t.Fatal("synchronous successful completion no longer ends ownership")
	}
}
