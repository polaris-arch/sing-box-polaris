package naive

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type inboundHandshakeFixture struct {
	entered, proceed, closed chan struct{}
	once                     sync.Once
}

func (c *inboundHandshakeFixture) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *inboundHandshakeFixture) Write(p []byte) (int, error)      { return len(p), nil }
func (c *inboundHandshakeFixture) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *inboundHandshakeFixture) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *inboundHandshakeFixture) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *inboundHandshakeFixture) SetDeadline(time.Time) error      { return nil }
func (c *inboundHandshakeFixture) SetReadDeadline(time.Time) error  { return nil }
func (c *inboundHandshakeFixture) SetWriteDeadline(time.Time) error { return nil }
func (c *inboundHandshakeFixture) HandshakeSuccess() error          { close(c.entered); <-c.proceed; return nil }

func TestRuntimeProtocolHandshakeIsJoinedBeforeCarrierRelease(t *testing.T) {
	f := newIngressFixture()
	construction, scope := ingressConstruction(f)
	defer scope.Close()
	state, err := newInboundRuntime(construction, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, graph := f.context()
	raw := &inboundHandshakeFixture{entered: make(chan struct{}), proceed: make(chan struct{}), closed: make(chan struct{})}
	conn, _, err := state.wrapConnection(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	graph.Release()
	if _, escaped := conn.(interface{ Upstream() any }); escaped {
		t.Fatal("raw protocol carrier escaped")
	}
	handshakeDone := make(chan struct{})
	go func() {
		if err := conn.(interface{ HandshakeSuccess() error }).HandshakeSuccess(); err != nil {
			t.Error(err)
		}
		close(handshakeDone)
	}()
	ingressWait(t, raw.entered)
	closed := make(chan struct{})
	go func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
		close(closed)
	}()
	ingressWait(t, raw.closed)
	ingressPending(t, closed)
	close(raw.proceed)
	ingressWait(t, handshakeDone)
	ingressWait(t, closed)
	if f.graphs.Load() != 0 {
		t.Fatal("carrier did not release after handshake completion")
	}
}

type inboundPanicHandshakeFixture struct{ inboundHandshakeFixture }

func (c *inboundPanicHandshakeFixture) HandshakeSuccess() error { panic("handshake fixture") }
func TestRuntimeProtocolHandshakePanicRetainsUncertainty(t *testing.T) {
	f := newIngressFixture()
	construction, scope := ingressConstruction(f)
	defer scope.Close()
	state, err := newInboundRuntime(construction, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, graph := f.context()
	raw := &inboundPanicHandshakeFixture{closed: make(chan struct{})}
	conn, _, err := state.wrapConnection(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	graph.Release()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("handshake panic was hidden")
			}
		}()
		_ = conn.(interface{ HandshakeSuccess() error }).HandshakeSuccess()
	}()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := state.closeAndWait(); err == nil {
		t.Fatal("handshake panic lost sticky cleanup uncertainty")
	}
	if f.graphs.Load() == 0 {
		t.Fatal("unknown handshake operation was released")
	}
}
