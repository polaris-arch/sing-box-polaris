package tls

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
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

func TestRuntimeCleanupErrorPreservesTypedCauseWithoutBenignScopeFiltering(t *testing.T) {
	for _, signal := range []error{
		context.Canceled, context.DeadlineExceeded, io.EOF, net.ErrClosed,
		io.ErrClosedPipe, os.ErrClosed, syscall.EPIPE, syscall.ECONNRESET, syscall.ENOTCONN,
		http.ErrServerClosed, outbound.ErrRuntimeClosePending,
	} {
		t.Run(signal.Error(), func(t *testing.T) {
			original := &net.OpError{Op: "close", Net: "tls", Err: signal}
			err := NewRuntimeCleanupError(original)
			var typed *net.OpError
			if !errors.Is(err, original) || !errors.As(err, &typed) || typed != original || errors.Is(err, signal) || !IsRuntimeCleanupIncomplete(err) {
				t.Fatal("typed cause or opaque completion contract lost", err)
			}
			scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
			scope.Add(func() error { return err })
			if result := scope.Close(); result == nil || !errors.Is(result, original) || errors.Is(result, signal) || !IsRuntimeCleanupIncomplete(result) {
				t.Fatal("Scope filtered failed TLS cleanup", result)
			}
		})
	}
}

type runtimeOwnedHandshakeFailureConfig struct {
	ServerConfig
	failure    error
	raw        *runtimeHandshakeConn
	handshakes atomic.Int32
}

func (*runtimeOwnedHandshakeFailureConfig) HandshakeTimeout() time.Duration { return 0 }
func (c *runtimeOwnedHandshakeFailureConfig) failedProvider(conn net.Conn) (Conn, error) {
	var ok bool
	c.raw, ok = conn.(*runtimeHandshakeConn)
	if !ok {
		return nil, errors.New("TLS fixture did not receive the actual owned handshake carrier")
	}
	return &runtimeOwnedHandshakeFailureConn{runtimeFailureProvider: &runtimeFailureProvider{Conn: conn}, failure: c.failure, calls: &c.handshakes}, nil
}

func (c *runtimeOwnedHandshakeFailureConfig) Client(conn net.Conn) (Conn, error) {
	return c.failedProvider(conn)
}

func (c *runtimeOwnedHandshakeFailureConfig) Server(conn net.Conn) (Conn, error) {
	return c.failedProvider(conn)
}

type runtimeOwnedHandshakeFailureConn struct {
	*runtimeFailureProvider
	failure error
	calls   *atomic.Int32
}

func (c *runtimeOwnedHandshakeFailureConn) HandshakeContext(context.Context) error {
	c.calls.Add(1)
	return c.failure
}

func TestRuntimeActualClientAndServerDoubleFailurePreservesCausesAndOwner(t *testing.T) {
	signals := []error{
		context.Canceled, context.DeadlineExceeded, io.EOF, net.ErrClosed,
		io.ErrClosedPipe, os.ErrClosed, syscall.EPIPE, syscall.ECONNRESET, syscall.ENOTCONN,
		http.ErrServerClosed, outbound.ErrRuntimeClosePending,
	}
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			handshakeFailure := errors.New("actual controlled TLS handshake business failure")
			closeFailure := &net.OpError{Op: "close", Net: "tls", Err: errors.New("actual controlled raw close business failure")}
			config := &runtimeOwnedHandshakeFailureConfig{failure: errors.Join(append([]error{handshakeFailure}, signals...)...)}
			base := newRuntimeFailureRaw()
			raw := &runtimeFailureProvider{Conn: base, closeError: errors.Join(append([]error{closeFailure}, signals...)...)}
			source := &runtimeFailureSource{}
			scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
			ctx := adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), source)
			conn, err := outbound.DialRuntimeConn(ctx, source, func(ctx context.Context) (net.Conn, error) {
				if side == "client" {
					return clientHandshakeOwned(ctx, raw, config)
				}
				return serverHandshakeOwned(ctx, raw, config)
			})
			var typed *net.OpError
			if conn != nil || !errors.Is(err, handshakeFailure) || !errors.Is(err, closeFailure) || !errors.As(err, &typed) || typed != closeFailure || !IsRuntimeCleanupIncomplete(err) {
				t.Fatal("actual owned handshake/raw close branch lost a cause or debt", err)
			}
			if config.handshakes.Load() != 1 || config.raw == nil || raw.closes.Load() != 1 || base.closes.Load() != 1 || source.refs.Load() != 1 {
				t.Fatal("failed handshake/raw close was not executed once or released its exact owner")
			}
			terminal := config.raw.fence.RuntimeCloseAndWait()
			if !errors.Is(terminal, closeFailure) || config.raw.fence.RuntimeCloseAndWait() != terminal || raw.closes.Load() != 1 {
				t.Fatal("raw close failure was not sticky and joined", terminal)
			}
			registered, registerErr := outbound.RegisterRuntimeCleanup(ctx, func() error { return errors.Join(err, config.raw.fence.RuntimeCloseAndWait()) })
			if !registered || registerErr != nil {
				t.Fatal("actual construction cleanup was not registered", registerErr)
			}
			result := scope.Close()
			if !errors.Is(result, handshakeFailure) || !errors.Is(result, closeFailure) || !errors.As(result, &typed) || typed != closeFailure || !IsRuntimeCleanupIncomplete(result) || source.refs.Load() != 1 {
				t.Fatal("Scope lost either real cause or failed resource ownership", result)
			}
			for _, signal := range signals {
				if errors.Is(err, signal) || errors.Is(terminal, signal) || errors.Is(result, signal) {
					t.Fatal("actual failed cleanup became filterable as a benign completion", signal, result)
				}
			}
		})
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
