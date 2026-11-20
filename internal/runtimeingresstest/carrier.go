// Package runtimeingresstest holds the carrier fixtures shared by protocol tests.
package runtimeingresstest

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

type CarrierFixture struct {
	Context    context.Context
	Wrap       func(context.Context, net.Conn, N.CloseHandlerFunc) (net.Conn, N.CloseHandlerFunc, error)
	Release    func()
	Graphs     *atomic.Int64
	CloseOwner func() error
}

func (f CarrierFixture) wrap(t *testing.T, raw net.Conn, onClose N.CloseHandlerFunc) (net.Conn, N.CloseHandlerFunc) {
	t.Helper()
	defer f.Release()
	conn, closeCarrier, err := f.Wrap(f.Context, raw, onClose)
	if err != nil {
		t.Fatal(err)
	}
	if closeCarrier == nil {
		t.Fatal("carrier was returned without cleanup")
	}
	return conn, closeCarrier
}

type handshakeFixture struct {
	entered, proceed, closed chan struct{}
	once                     sync.Once
}

func (c *handshakeFixture) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *handshakeFixture) Write(p []byte) (int, error)      { return len(p), nil }
func (c *handshakeFixture) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *handshakeFixture) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *handshakeFixture) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *handshakeFixture) SetDeadline(time.Time) error      { return nil }
func (c *handshakeFixture) SetReadDeadline(time.Time) error  { return nil }
func (c *handshakeFixture) SetWriteDeadline(time.Time) error { return nil }
func (c *handshakeFixture) HandshakeSuccess() error          { close(c.entered); <-c.proceed; return nil }

func wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("carrier handshake did not reach its ownership barrier")
	}
}

func CheckHandshakeJoinsBeforeRelease(t *testing.T, f CarrierFixture) {
	t.Helper()
	raw := &handshakeFixture{entered: make(chan struct{}), proceed: make(chan struct{}), closed: make(chan struct{})}
	closeReason := errors.New("fixture close reason")
	onCloseCalls := 0
	conn, closeCarrier := f.wrap(t, raw, func(err error) {
		onCloseCalls++
		if err != closeReason {
			t.Errorf("close reason changed: %v", err)
		}
	})
	if _, escaped := conn.(interface{ Upstream() any }); escaped {
		t.Fatal("raw protocol carrier escaped")
	}
	if _, escaped := conn.(syscall.Conn); escaped {
		t.Fatal("raw syscall access escaped")
	}
	handshakeDone := make(chan struct{})
	go func() {
		if err := conn.(interface{ HandshakeSuccess() error }).HandshakeSuccess(); err != nil {
			t.Error(err)
		}
		close(handshakeDone)
	}()
	var unblock sync.Once
	defer unblock.Do(func() { close(raw.proceed) })
	wait(t, raw.entered)
	closed := make(chan struct{})
	go func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
		close(closed)
	}()
	wait(t, raw.closed)
	select {
	case <-closed:
		t.Fatal("carrier closed before the admitted handshake returned")
	default:
	}
	unblock.Do(func() { close(raw.proceed) })
	wait(t, handshakeDone)
	wait(t, closed)
	closeCarrier(closeReason)
	closeCarrier(nil)
	if onCloseCalls != 1 {
		t.Fatalf("upstream close callback invoked %d times", onCloseCalls)
	}
	if f.Graphs.Load() != 0 {
		t.Fatal("carrier did not release after handshake completion")
	}
}

type panicHandshakeFixture struct{ handshakeFixture }

func (c *panicHandshakeFixture) HandshakeSuccess() error { panic("handshake fixture") }

func CheckHandshakePanicRetainsUncertainty(t *testing.T, f CarrierFixture) {
	t.Helper()
	raw := &panicHandshakeFixture{closed: make(chan struct{})}
	conn, closeCarrier := f.wrap(t, raw, nil)
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
	closeCarrier(nil)
	if err := f.CloseOwner(); err == nil {
		t.Fatal("handshake panic lost sticky cleanup uncertainty")
	}
	if f.Graphs.Load() == 0 {
		t.Fatal("unknown handshake operation was released")
	}
}
