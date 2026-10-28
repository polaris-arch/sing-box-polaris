package socks

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing/common/auth"
	N "github.com/sagernet/sing/common/network"
)

type handoffConnFixture struct {
	input  *bytes.Reader
	output bytes.Buffer
	closed bool
}

func (c *handoffConnFixture) Read(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.input.Read(p)
}

func (c *handoffConnFixture) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.output.Write(p)
}
func (c *handoffConnFixture) Close() error { c.closed = true; return nil }
func (*handoffConnFixture) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}
}

func (*handoffConnFixture) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
}
func (*handoffConnFixture) SetDeadline(time.Time) error      { return nil }
func (*handoffConnFixture) SetReadDeadline(time.Time) error  { return nil }
func (*handoffConnFixture) SetWriteDeadline(time.Time) error { return nil }

type handoffRouterFixture struct {
	adapter.Router
	connection net.Conn
	onClose    N.CloseHandlerFunc
	terminal   bool
}

func TestSOCKSAndMixedConstructorsPreserveSuccessfulHandoff(t *testing.T) {
	for _, kind := range []string{"socks", "mixed"} {
		t.Run(kind, func(t *testing.T) {
			router := new(handoffRouterFixture)
			logger := log.NewNOPFactory().Logger()
			var entry adapter.Inbound
			var err error
			if kind == "mixed" {
				entry, err = mixed.NewInbound(context.Background(), router, logger, "mixed", option.HTTPMixedInboundOptions{})
			} else {
				entry, err = NewInbound(context.Background(), router, logger, "socks", option.SocksInboundOptions{})
			}
			if err != nil {
				t.Fatal(err)
			}
			// Construct only: no listener Start, bind, or system-proxy action.
			raw := &handoffConnFixture{input: bytes.NewReader([]byte{5, 1, 0, 5, 1, 0, 1, 203, 0, 113, 10, 0, 80})}
			terminals := 0
			entry.(adapter.ConnectionHandler).NewConnection(context.Background(), raw, adapter.InboundContext{}, func(error) { terminals++; _ = raw.Close() })
			if router.connection == nil || terminals != 0 || raw.closed {
				t.Fatal("constructor path ended ownership at successful handoff")
			}
			if err := N.ReportConnHandshakeSuccess(router.connection, raw); err != nil {
				t.Fatal(err)
			}
			if raw.output.Len() != 12 {
				t.Fatalf("incomplete auth/CONNECT reply: %d bytes", raw.output.Len())
			}
			router.onClose(nil)
			if terminals != 1 || !raw.closed {
				t.Fatal("constructor path lost terminal ownership")
			}
		})
	}
}

func (r *handoffRouterFixture) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.connection, r.onClose = conn, onClose
	if r.terminal {
		onClose(nil)
	}
}

func TestSOCKSConnectSuccessTransfersOwnedCarrier(t *testing.T) {
	for _, test := range []struct {
		name     string
		request  []byte
		response []byte
	}{
		{"SOCKS4", []byte{4, 1, 0, 80, 203, 0, 113, 10, 0}, []byte{0, 90, 39, 16, 127, 0, 0, 1}},
		{"SOCKS5", []byte{5, 1, 0, 5, 1, 0, 1, 203, 0, 113, 10, 0, 80}, []byte{5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 39, 16}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := &handoffConnFixture{input: bytes.NewReader(test.request)}
			var releases atomic.Int32
			owned := outbound.WrapRuntimeConn(context.Background(), func() { releases.Add(1) }, raw)
			defer owned.Close()
			router := new(handoffRouterFixture)
			h := &Inbound{router: router, logger: log.NewNOPFactory().Logger()}
			terminals := 0
			h.NewConnection(context.Background(), owned, adapter.InboundContext{}, func(error) {
				terminals++
				_ = owned.Close()
			})
			if router.connection == nil || terminals != 0 || releases.Load() != 0 || raw.closed {
				t.Fatal("asynchronous handoff was mistaken for terminal connection completion")
			}
			// Force success through the actual LazyConn before any application I/O.
			if err := N.ReportConnHandshakeSuccess(router.connection, raw); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw.output.Bytes(), test.response) {
				t.Fatalf("response = %v, want %v", raw.output.Bytes(), test.response)
			}
			if _, err := router.connection.Write([]byte("still owned")); err != nil {
				t.Fatal(err)
			}
			router.onClose(nil)
			if terminals != 1 || releases.Load() != 1 || !raw.closed {
				t.Fatal("actual terminal callback did not release the carrier exactly once")
			}
		})
	}
}

func TestSOCKSHandlerSynchronousCompletionIsNotRepeated(t *testing.T) {
	raw := &handoffConnFixture{input: bytes.NewReader([]byte{5, 1, 0, 5, 1, 0, 1, 203, 0, 113, 10, 0, 80})}
	router := &handoffRouterFixture{terminal: true}
	h := &Inbound{router: router, logger: log.NewNOPFactory().Logger()}
	terminals := 0
	h.NewConnection(context.Background(), raw, adapter.InboundContext{}, func(error) { terminals++; _ = raw.Close() })
	if terminals != 1 || !raw.closed {
		t.Fatal("handler-owned synchronous completion was repeated by the handshake caller")
	}
}

func TestSOCKSHandshakeFailureRemainsTerminal(t *testing.T) {
	for _, test := range []struct {
		name          string
		request       []byte
		authenticator *auth.Authenticator
	}{
		{name: "truncated", request: []byte{5, 1}},
		{name: "invalid-version", request: []byte{9}},
		{name: "unsupported-command", request: []byte{5, 1, 0, 5, 2, 0, 1, 203, 0, 113, 10, 0, 80}},
		{name: "authentication", request: []byte{4, 1, 0, 80, 203, 0, 113, 10, 'b', 'a', 'd', 0}, authenticator: auth.NewAuthenticator([]auth.User{{Username: "allowed"}})},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := &handoffConnFixture{input: bytes.NewReader(test.request)}
			router := new(handoffRouterFixture)
			h := &Inbound{router: router, logger: log.NewNOPFactory().Logger(), authenticator: test.authenticator}
			terminals := 0
			var terminalError error
			h.NewConnection(context.Background(), raw, adapter.InboundContext{}, func(err error) { terminals++; terminalError = err })
			if terminals != 1 || terminalError == nil || !raw.closed || router.connection != nil {
				t.Fatal("failed handshake did not close and report its actual error")
			}
		})
	}
}

func TestSOCKSRouteRejectionRetainsOriginalError(t *testing.T) {
	// The parser has transferred ownership before the asynchronous router can
	// reject the flow. Its error must not be replaced by a second nil callback.
	raw := &handoffConnFixture{input: bytes.NewReader([]byte{5, 1, 0, 5, 1, 0, 1, 203, 0, 113, 10, 0, 80})}
	router := new(handoffRouterFixture)
	h := &Inbound{router: router, logger: log.NewNOPFactory().Logger()}
	var reported error
	terminals := 0
	h.NewConnection(context.Background(), raw, adapter.InboundContext{}, func(err error) { terminals++; reported = err })
	rejected := errors.New("route rejected by subscription policy")
	N.CloseOnHandshakeFailure(router.connection, router.onClose, rejected)
	if terminals != 1 || !errors.Is(reported, rejected) || !raw.closed {
		t.Fatal("asynchronous rejection lost its error or ownership")
	}
}
