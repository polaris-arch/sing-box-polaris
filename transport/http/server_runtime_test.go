package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type heldRuntimeHTTPHandler struct{ entered, finish chan struct{} }

func (h *heldRuntimeHTTPHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	close(h.entered)
	<-h.finish
	_ = conn.Close()
	onClose(nil)
}

func (*heldRuntimeHTTPHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	panic("unexpected packet fixture")
}

func TestRuntimeHTTPUpstreamInvocationRetainsBeforeScheduling(t *testing.T) {
	closed := make(chan struct{})
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "server", Sequence: 1}, nil, func() error { close(closed); return nil })
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), lease)
	handler := &heldRuntimeHTTPHandler{entered: make(chan struct{}), finish: make(chan struct{})}
	conn := newUpstreamConn(ctx, handler, M.Socksaddr{}, M.Socksaddr{})
	waitHTTPBarrier(t, handler.entered)
	lease.Release()
	owner.Seal()
	assertHTTPPending(t, closed)
	close(handler.finish)
	waitHTTPBarrier(t, conn.done)
	waitHTTPBarrier(t, closed)
	_ = conn.Close()
}

func TestRuntimeHTTPRejectsLateHandlerBeforeTouchingRetiredServer(t *testing.T) {
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "server", Sequence: 2}, nil, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), lease)
	lease.Release()
	owner.Seal()
	request := httptest.NewRequest(stdhttp.MethodGet, "http://example.test/", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	// A nil retired server makes any access before ownership admission observable.
	(&httpHandler{}).ServeHTTP(response, request)
	if response.Code != stdhttp.StatusServiceUnavailable {
		t.Fatal("stale handler admitted")
	}
}

func TestHTTP1ProbeConnectHandshake(t *testing.T) {
	const probeHeader = "X-Polaris-Probe: 1\r\n"
	const backgroundProbeHeader = "X-Polaris-Probe: background\r\n"
	capacityErr := fmt.Errorf("dial outbound: %w", adapter.ErrOutboundCapacity)
	for _, tc := range []struct {
		name           string
		probeListener  bool
		remoteIP       string
		probeHeader    string
		authenticator  *auth.Authenticator
		dialErr        error
		wantStatus     int
		wantOutcome    string
		wantBackground bool
	}{
		{name: "capacity busy", probeListener: true, remoteIP: "127.0.0.1", probeHeader: probeHeader, dialErr: capacityErr, wantStatus: 503, wantOutcome: "budget-busy"},
		{name: "background capacity busy", probeListener: true, remoteIP: "127.0.0.1", probeHeader: backgroundProbeHeader, dialErr: capacityErr, wantStatus: 503, wantOutcome: "budget-busy", wantBackground: true},
		{name: "background foreground slot reserved", probeListener: true, remoteIP: "127.0.0.1", probeHeader: backgroundProbeHeader, dialErr: adapter.ErrOutboundForegroundSlot, wantStatus: 503, wantOutcome: "budget-busy", wantBackground: true},
		{name: "multiple capacity refusals", probeListener: true, remoteIP: "127.0.0.1", probeHeader: backgroundProbeHeader, dialErr: errors.Join(adapter.ErrOutboundForegroundSlot, adapter.ErrOutboundCapacity), wantStatus: 503, wantOutcome: "budget-busy", wantBackground: true},
		{name: "network failure with hard capacity", probeListener: true, remoteIP: "127.0.0.1", probeHeader: backgroundProbeHeader, dialErr: errors.Join(adapter.ErrOutboundCapacity, net.ErrClosed), wantStatus: 502, wantBackground: true},
		{name: "network failure with a reserved slot", probeListener: true, remoteIP: "127.0.0.1", probeHeader: backgroundProbeHeader, dialErr: errors.Join(adapter.ErrOutboundForegroundSlot, net.ErrClosed), wantStatus: 502, wantBackground: true},
		{name: "success", probeListener: true, remoteIP: "::1", probeHeader: probeHeader, wantStatus: 200},
		{name: "untyped dial error", probeListener: true, remoteIP: "127.0.0.1", probeHeader: probeHeader, dialErr: errors.New(adapter.ErrOutboundCapacity.Error()), wantStatus: 502},
		{name: "no opt in", probeListener: true, remoteIP: "127.0.0.1", dialErr: capacityErr, wantStatus: 200},
		{name: "ordinary listener", remoteIP: "127.0.0.1", probeHeader: backgroundProbeHeader, dialErr: capacityErr, wantStatus: 200},
		{name: "forwarded loopback is not a physical peer", probeListener: true, remoteIP: "192.0.2.10", probeHeader: backgroundProbeHeader + "X-Forwarded-For: 127.0.0.1\r\n", dialErr: capacityErr, wantStatus: 200},
		{name: "authentication required", probeListener: true, remoteIP: "127.0.0.1", probeHeader: probeHeader, authenticator: auth.NewAuthenticator([]auth.User{{Username: "probe", Password: "secret"}}), wantStatus: 407},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, wire := net.Pipe()
			defer client.Close()
			defer wire.Close()
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			conn := probePeerConn{Conn: wire, peer: &net.TCPAddr{IP: net.ParseIP(tc.remoteIP)}}
			server := NewServer(ServerOptions{
				HTTP1:         true,
				ProbeConnect:  tc.probeListener,
				Logger:        log.NewNOPFactory().Logger(),
				Authenticator: tc.authenticator,
			})
			background := make(chan bool, 1)
			handler := probeHandshakeHandler{dialErr: tc.dialErr, background: background}
			go server.ServeConnection(context.Background(), conn, NewReader(conn), handler, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
			request := "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nConnection: close\r\n" + tc.probeHeader + "\r\n"
			if _, err := io.WriteString(client, request); err != nil {
				t.Fatal(err)
			}
			response, err := stdhttp.ReadResponse(bufio.NewReader(client), &stdhttp.Request{Method: stdhttp.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			if outcome := response.Header.Get("X-Polaris-Probe-Outcome"); response.StatusCode != tc.wantStatus || outcome != tc.wantOutcome {
				t.Fatalf("CONNECT result = (%d, %q), want (%d, %q)", response.StatusCode, outcome, tc.wantStatus, tc.wantOutcome)
			}
			if tc.wantStatus != stdhttp.StatusProxyAuthRequired {
				select {
				case got := <-background:
					if got != tc.wantBackground {
						t.Fatalf("background context = %v, want %v", got, tc.wantBackground)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("CONNECT did not reach the handler")
				}
			}
		})
	}
}

type probePeerConn struct {
	net.Conn
	peer net.Addr
}

func (c probePeerConn) RemoteAddr() net.Addr { return c.peer }

type probeHandshakeHandler struct {
	Handler
	dialErr    error
	background chan<- bool
}

func (h probeHandshakeHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.background <- urltest.IsBackgroundProbe(ctx)
	if h.dialErr != nil {
		N.CloseOnHandshakeFailure(conn, onClose, h.dialErr)
		return
	}
	_ = N.ReportConnHandshakeSuccess(conn, nil)
	_ = conn.Close()
}
