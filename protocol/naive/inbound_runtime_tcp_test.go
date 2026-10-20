package naive

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/runtimeingress"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type naiveTestConn struct {
	closed chan struct{}
	once   sync.Once
}

func (c *naiveTestConn) Read([]byte) (int, error) { <-c.closed; return 0, io.EOF }
func (c *naiveTestConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}
func (c *naiveTestConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *naiveTestConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *naiveTestConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *naiveTestConn) SetDeadline(time.Time) error      { return nil }
func (c *naiveTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *naiveTestConn) SetWriteDeadline(time.Time) error { return nil }
func TestNaivePrivateAcceptorPreservesPhysicalCarrier(t *testing.T) {
	f := newIngressFixture()
	construction, scope := ingressConstruction(f)
	defer scope.Close()
	state, err := newInboundRuntime(construction, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	owner := newRuntimeNaiveTCP(&Inbound{ctx: construction, runtime: state})
	ctx, graph := f.context()
	raw := &naiveTestConn{closed: make(chan struct{})}
	carrier := outbound.WrapRuntimeConn(ctx, graph.Release, raw)
	handed := make(chan struct{})
	go func() { owner.acceptor.NewConnection(ctx, carrier, adapter.InboundContext{}, nil); close(handed) }()
	actual, err := (&runtimeNaiveListener{runtimeNaiveTCP: owner}).Accept()
	if err != nil {
		t.Fatal(err)
	}
	ingressWait(t, handed)
	lineage := runtimeingress.Context(context.Background(), actual)
	if _, ok := adapter.RuntimeLeaseFromContext(lineage); !ok {
		t.Fatal("physical carrier lineage was replaced")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	ingressWait(t, raw.closed)
	if f.graphs.Load() != 0 {
		t.Fatal("physical carrier graph did not drain")
	}
}

type naiveDeadlineWriter struct {
	header   http.Header
	deadline bool
	err      error
}

func (w *naiveDeadlineWriter) Header() http.Header              { return w.header }
func (w *naiveDeadlineWriter) Write(p []byte) (int, error)      { return len(p), nil }
func (w *naiveDeadlineWriter) WriteHeader(int)                  {}
func (w *naiveDeadlineWriter) SetWriteDeadline(time.Time) error { w.deadline = true; return w.err }
func TestNaiveResponseCloseInterruptsWritesBeforeCarrierJoin(t *testing.T) {
	raw := &naiveTestConn{closed: make(chan struct{})}
	writer := &naiveDeadlineWriter{header: make(http.Header)}
	conn := &runtimeNaiveResponseConn{Conn: raw, writer: writer}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !writer.deadline {
		t.Fatal("response writer was not interrupted")
	}
	ingressWait(t, raw.closed)
}

func TestNaiveUnsupportedResponseInterruptionRemainsUncertain(t *testing.T) {
	raw := &naiveTestConn{closed: make(chan struct{})}
	writer := &naiveDeadlineWriter{header: make(http.Header), err: http.ErrNotSupported}
	if err := (&runtimeNaiveResponseConn{Conn: raw, writer: writer}).Close(); err == nil || errors.Is(err, http.ErrNotSupported) {
		t.Fatal("uncertainty was absent or filterable", err)
	}
	ingressWait(t, raw.closed)
}

type (
	naiveRouteFixture struct {
		adapter.ConnectionRouterEx
		handed chan naiveRoutedConn
	}
	naiveRoutedConn struct {
		conn    net.Conn
		onClose N.CloseHandlerFunc
	}
)

func (r naiveRouteFixture) RouteConnectionEx(_ context.Context, c net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.handed <- naiveRoutedConn{c, onClose}
}

type naiveBlockedResponse struct {
	naiveTestConn
	entered, interrupted chan struct{}
	interruptOnce        sync.Once
}

func (w *naiveBlockedResponse) Write([]byte) (int, error) {
	close(w.entered)
	<-w.interrupted
	return 0, net.ErrClosed
}
func (w *naiveBlockedResponse) Header() http.Header { return make(http.Header) }
func (w *naiveBlockedResponse) WriteHeader(int)     {}
func (w *naiveBlockedResponse) SetWriteDeadline(time.Time) error {
	w.interruptOnce.Do(func() { close(w.interrupted) })
	return nil
}

func TestNaiveStagedRouteCloseInterruptsBlockedResponseBeforeJoining(t *testing.T) {
	f := newIngressFixture()
	construction, scope := ingressConstruction(f)
	defer scope.Close()
	state, err := newInboundRuntime(construction, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	route := naiveRouteFixture{handed: make(chan naiveRoutedConn, 1)}
	n := &Inbound{ctx: construction, runtime: state, router: route, logger: log.NewNOPFactory().Logger(), listener: listener.New(listener.Options{Context: construction, Logger: log.NewNOPFactory().Logger()})}
	ctx, graph := f.context()
	raw := &naiveBlockedResponse{naiveTestConn: naiveTestConn{closed: make(chan struct{})}, entered: make(chan struct{}), interrupted: make(chan struct{})}
	handlerDone := make(chan struct{})
	go func() {
		n.newConnection(ctx, true, &runtimeNaiveResponseConn{Conn: raw, writer: raw}, "", M.Socksaddr{}, M.Socksaddr{})
		close(handlerDone)
	}()
	var handed naiveRoutedConn
	select {
	case handed = <-route.handed:
	case <-time.After(5 * time.Second):
		t.Fatal("route watchdog")
	}
	graph.Release()
	writeDone := make(chan struct{})
	go func() { _, _ = handed.conn.Write([]byte{1}); close(writeDone) }()
	ingressWait(t, raw.entered)
	closeDone := make(chan struct{})
	go func() {
		if err := handed.conn.Close(); err != nil {
			t.Error(err)
		}
		handed.onClose(nil)
		close(closeDone)
	}()
	ingressWait(t, raw.interrupted)
	ingressWait(t, writeDone)
	ingressWait(t, closeDone)
	ingressWait(t, handlerDone)
	if f.graphs.Load() != 0 {
		t.Fatal("response graph remained after real close and handler return")
	}
}
