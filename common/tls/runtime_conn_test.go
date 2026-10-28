package tls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
)

type runtimeTLSBarrier struct {
	entered, release, closed chan struct{}
	once                     sync.Once
	closes                   atomic.Int32
}

func (c *runtimeTLSBarrier) Read([]byte) (int, error) {
	close(c.entered)
	<-c.release
	return 0, io.EOF
}
func (c *runtimeTLSBarrier) Write(p []byte) (int, error) { return len(p), nil }
func (c *runtimeTLSBarrier) Close() error {
	c.closes.Add(1)
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *runtimeTLSBarrier) LocalAddr() net.Addr                    { return &net.TCPAddr{} }
func (c *runtimeTLSBarrier) RemoteAddr() net.Addr                   { return &net.TCPAddr{} }
func (c *runtimeTLSBarrier) SetDeadline(time.Time) error            { return nil }
func (c *runtimeTLSBarrier) SetReadDeadline(time.Time) error        { return nil }
func (c *runtimeTLSBarrier) SetWriteDeadline(time.Time) error       { return nil }
func (c *runtimeTLSBarrier) HandshakeContext(context.Context) error { return nil }
func (c *runtimeTLSBarrier) ConnectionState() ConnectionState {
	return ConnectionState{HandshakeComplete: true}
}
func (c *runtimeTLSBarrier) NetConn() net.Conn { return c }

func TestRuntimeTLSCloseJoinsProviderMethod(t *testing.T) {
	provider := &runtimeTLSBarrier{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	guarded, fence := outbound.WrapRuntimeOwnedConn(provider)
	conn := &runtimeTLSConn{Conn: guarded, tlsConn: provider, raw: guarded, fence: fence, state: provider.ConnectionState()}
	readDone := make(chan struct{})
	go func() { defer close(readDone); _, _ = conn.Read(nil) }()
	<-provider.entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()
	<-provider.closed
	select {
	case <-closeDone:
		t.Fatal("provider read tail was not joined")
	default:
	}
	close(provider.release)
	<-readDone
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if provider.closes.Load() != 1 {
		t.Fatal("late TLS cancellation closed raw provider again")
	}
}

func TestRuntimeTLSInspectionJoinsConstructor(t *testing.T) {
	provider := &runtimeTLSBarrier{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	guarded, fence := outbound.WrapRuntimeOwnedConn(provider)
	conn := &runtimeTLSConn{Conn: guarded, tlsConn: provider, raw: guarded, fence: fence}
	entered, finish, inspected := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(inspected)
		_ = WithRuntimeTLSInspection(conn, func(native net.Conn) error {
			if native != provider {
				panic("wrong TLS inspection target")
			}
			close(entered)
			<-finish
			return nil
		})
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	<-provider.closed
	select {
	case <-closed:
		t.Fatal("inspection tail was not joined")
	default:
	}
	close(finish)
	<-inspected
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := WithRuntimeTLSInspection(conn, func(net.Conn) error { t.Fatal("inspection admitted after seal"); return nil }); err == nil {
		t.Fatal("sealed inspection succeeded")
	}
}

func TestRuntimeCleanupErrorDoesNotUnwrapCancellation(t *testing.T) {
	err := NewRuntimeCleanupError(context.Canceled)
	if !IsRuntimeCleanupIncomplete(err) {
		t.Fatal("cleanup marker missing")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("Scope would filter cleanup uncertainty")
	}
}

// Embedding supplies the unrelated configuration methods; the handshake path
// supplies HandshakeTimeout and Server before the provider handshake.
type runtimeServerFixture struct {
	ServerConfig
	provider Conn
	err      error
}

func (c *runtimeServerFixture) Server(net.Conn) (Conn, error)   { return c.provider, c.err }
func (c *runtimeServerFixture) HandshakeTimeout() time.Duration { return 0 }

func TestRuntimeServerConstructionFailureClosesRawCarrier(t *testing.T) {
	raw := &runtimeTLSBarrier{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	failure := errors.New("injected server constructor failure")
	_, err := serverHandshakeOwned(context.Background(), raw, &runtimeServerFixture{err: failure})
	if !errors.Is(err, failure) {
		t.Fatalf("lost server error: %v", err)
	}
	if raw.closes.Load() != 1 {
		t.Fatal("failed server handshake did not join raw close")
	}
}

func TestRuntimeServerSuccessKeepsGuardedProvider(t *testing.T) {
	raw := &runtimeTLSBarrier{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	provider := &runtimeTLSBarrier{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	conn, err := serverHandshakeOwned(context.Background(), raw, &runtimeServerFixture{provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	if conn == provider || conn.NetConn() == raw {
		t.Fatal("staged server exposed an unguarded provider or raw carrier")
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if raw.closes.Load() != 1 || provider.closes.Load() != 1 {
		t.Fatal("server provider/raw cleanup was not joined exactly once")
	}
}
