package tls

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/logger"
)

type runtimeFailureProvider struct {
	net.Conn
	closeError error
	panicClose bool
	closes     atomic.Int32
}

func (c *runtimeFailureProvider) Close() error {
	if c.closes.Add(1) > 1 {
		return net.ErrClosed
	}
	if c.panicClose {
		panic("controlled provider close panic")
	}
	return errors.Join(c.Conn.Close(), c.closeError)
}
func (c *runtimeFailureProvider) HandshakeContext(context.Context) error { return nil }
func (c *runtimeFailureProvider) ConnectionState() ConnectionState {
	return ConnectionState{HandshakeComplete: true}
}
func (c *runtimeFailureProvider) NetConn() net.Conn { return c.Conn }

type (
	runtimeFailureSource struct{ refs atomic.Int32 }
	runtimeFailureLease  struct {
		source   *runtimeFailureSource
		released atomic.Bool
	}
)

func (*runtimeFailureSource) ID() adapter.RuntimeResourceID {
	return adapter.RuntimeResourceID{Incarnation: "tls-failed-handshake-test", Sequence: 1}
}

func (s *runtimeFailureSource) Acquire() (adapter.RuntimeResourceLease, error) {
	s.refs.Add(1)
	return &runtimeFailureLease{source: s}, nil
}
func (l *runtimeFailureLease) ID() adapter.RuntimeResourceID { return l.source.ID() }
func (*runtimeFailureLease) Retiring() <-chan struct{}       { return nil }
func (l *runtimeFailureLease) Fork() (adapter.RuntimeResourceLease, error) {
	if l.released.Load() {
		return nil, net.ErrClosed
	}
	return l.source.Acquire()
}

func (l *runtimeFailureLease) Release() {
	if l.released.CompareAndSwap(false, true) {
		l.source.refs.Add(-1)
	}
}

type runtimeFailureConfig struct {
	Config
	handshake func(context.Context, net.Conn) (Conn, error)
}

func (*runtimeFailureConfig) HandshakeTimeout() time.Duration { return 0 }
func (c *runtimeFailureConfig) ClientHandshake(ctx context.Context, conn net.Conn) (Conn, error) {
	return c.handshake(ctx, conn)
}

type runtimeFailureKTLSConfig struct {
	ServerConfig
	provider Conn
}

func (*runtimeFailureKTLSConfig) HandshakeTimeout() time.Duration { return 0 }
func (c *runtimeFailureKTLSConfig) Client(net.Conn) (Conn, error) { return c.provider, nil }
func (c *runtimeFailureKTLSConfig) Server(net.Conn) (Conn, error) { return c.provider, nil }

func newRuntimeFailureRaw() *runtimeTLSBarrier {
	return &runtimeTLSBarrier{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
}

func TestRuntimeTLSFailurePairJoinsRawMethod(t *testing.T) {
	raw := newRuntimeFailureRaw()
	guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
	transport := &runtimeHandshakeConn{Conn: guarded, fence: fence}
	provider := &runtimeFailureProvider{Conn: transport}
	readDone := make(chan struct{})
	go func() { defer close(readDone); _, _ = transport.Read(nil) }()
	<-raw.entered
	cause := errors.New("original authentication failure")
	done := make(chan error, 1)
	go func() { done <- runtimeProviderFailure(provider, transport, cause) }()
	<-raw.closed
	select {
	case <-done:
		t.Fatal("raw method tail not joined")
	default:
	}
	close(raw.release)
	<-readDone
	if err := <-done; err != cause {
		t.Fatalf("first cause lost: %v", err)
	}
	if raw.closes.Load() != 1 || provider.closes.Load() != 1 {
		t.Fatal("provider/raw not closed once")
	}
	if _, err := fence.Acquire(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("raw admitted after cleanup")
	}
}

func TestRuntimeTLSFailurePairRepeatedConcurrentClose(t *testing.T) {
	raw := newRuntimeFailureRaw()
	guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
	transport := &runtimeHandshakeConn{Conn: guarded, fence: fence}
	provider := &runtimeFailureProvider{Conn: transport}
	_, outer := outbound.WrapRuntimeOwnedConn(runtimeProviderCloseConn(provider, transport))
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Go(func() { results <- outer.RuntimeCloseAndWait() })
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if raw.closes.Load() != 1 || provider.closes.Load() != 1 {
		t.Fatal("repeat called physical/provider close again")
	}
}

func TestRuntimeTLSFailureErrorClassification(t *testing.T) {
	real := errors.New("controlled actual provider close failure")
	for _, tc := range []struct {
		name string
		err  error
		pure bool
	}{
		{"closed", net.ErrClosed, true},
		{"pending", outbound.ErrRuntimeClosePending, true},
		{"joined-known", errors.Join(net.ErrClosed, outbound.ErrRuntimeClosePending), true},
		{"real", real, false},
		{"mixed", errors.Join(outbound.ErrRuntimeClosePending, real), false},
		{"opaque", NewRuntimeCleanupError(outbound.ErrRuntimeClosePending), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if runtimeTLSAlreadyClosed(tc.err) != tc.pure {
				t.Fatal("close classification differs")
			}
			raw := newRuntimeFailureRaw()
			guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
			transport := &runtimeHandshakeConn{Conn: guarded, fence: fence}
			provider := &runtimeFailureProvider{Conn: transport, closeError: tc.err}
			cause := errors.New("original failure")
			err := runtimeProviderFailure(provider, transport, cause)
			if tc.pure {
				if err != cause {
					t.Fatal(err)
				}
			} else {
				if !IsRuntimeCleanupIncomplete(err) {
					t.Fatal("real/opaque close error was swallowed")
				}
				if !errors.Is(err.(*runtimeCleanupError).cause, cause) {
					t.Fatal("original cause lost inside opaque marker")
				}
			}
		})
	}
}

func TestRuntimeTLSFailureUnknownTransportNoCompletion(t *testing.T) {
	raw := newRuntimeFailureRaw()
	guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
	// An opaque wrapper is deliberately not a constructor-bound private proof.
	unknown := struct{ net.Conn }{guarded}
	provider := &runtimeFailureProvider{Conn: unknown}
	if runtimeProviderCloseConn(provider, unknown) != provider {
		t.Fatal("unknown transport gained completion authority")
	}
	err := runtimeProviderFailure(provider, unknown, context.Canceled)
	if !IsRuntimeCleanupIncomplete(err) || errors.Is(err, context.Canceled) {
		t.Fatal("unknown cleanup filtered as cancellation")
	}
	if err = fence.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeTLSFailureAdmissionReleaseAndPreservedError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		closeError error
		panicClose bool
		uncertain  bool
	}{
		{name: "authentication"},
		{name: "cancel"},
		{name: "real-close-error", closeError: errors.New("real close failure"), uncertain: true},
		{name: "provider-panic", panicClose: true, uncertain: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := new(runtimeFailureSource)
			raw := newRuntimeFailureRaw()
			cause := errors.New("authentication rejected")
			if tc.name == "cancel" {
				cause = context.Canceled
			}
			config := &runtimeFailureConfig{handshake: func(_ context.Context, conn net.Conn) (Conn, error) {
				return nil, runtimeProviderFailure(&runtimeFailureProvider{Conn: conn, closeError: tc.closeError, panicClose: tc.panicClose}, conn, cause)
			}}
			_, err := outbound.DialRuntimeConn(context.Background(), source, func(ctx context.Context) (net.Conn, error) { return clientHandshakeOwned(ctx, raw, config) })
			if tc.uncertain {
				if !IsRuntimeCleanupIncomplete(err) || source.refs.Load() != 1 {
					t.Fatal("uncertain failed admission was released")
				}
			} else if err != cause || source.refs.Load() != 0 {
				t.Fatalf("cause/ref mismatch: %v/%d", err, source.refs.Load())
			}
			if raw.closes.Load() != 1 {
				t.Fatal("failed handshake raw was not physically closed once")
			}
		})
	}
}

// A raw transport must not also impersonate a TLS provider whose NetConn
// returns itself. Real pipe endpoints have no descriptor or unwrap interface;
// this observer keeps that finite transport shape while counting physical close.
type runtimeFailurePhysicalConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *runtimeFailurePhysicalConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestRuntimeTLSFailureKTLSClientServerKeepsCleanupError(t *testing.T) {
	// The real kTLS constructor can invoke its existing modprobe path as root.
	// This regression needs only an ordinary unprivileged constructor failure;
	// refuse privileged execution rather than loading a module or skipping PASS.
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Fatal("kTLS failure regression requires an unprivileged process")
	}
	for _, server := range []bool{false, true} {
		physical, peer := net.Pipe()
		defer physical.Close()
		defer peer.Close()
		if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		raw := &runtimeFailurePhysicalConn{Conn: physical}
		if _, ok := any(raw).(interface{ NetConn() net.Conn }); ok {
			t.Fatal("physical fixture exposes TLS NetConn")
		}
		if _, ok := any(raw).(interface{ Upstream() any }); ok {
			t.Fatal("physical fixture exposes an unwrap path")
		}
		if _, ok := any(raw).(syscall.Conn); ok {
			t.Fatal("pipe fixture exposes a descriptor")
		}
		guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
		transport := &runtimeHandshakeConn{Conn: guarded, fence: fence}
		provider := &runtimeFailureProvider{Conn: transport, closeError: errors.New("controlled provider close failure")}
		config := &runtimeFailureKTLSConfig{provider: provider}
		var err error
		if server {
			_, err = (&KTlSServerConfig{ServerConfig: config, logger: logger.NOP(), kernelTx: true}).ServerHandshake(context.Background(), transport)
		} else {
			_, err = (&KTLSClientConfig{Config: config, logger: logger.NOP(), kernelTx: true}).ClientHandshake(context.Background(), transport)
		}
		if !IsRuntimeCleanupIncomplete(err) {
			t.Fatalf("kTLS constructor discarded cleanup error: %v", err)
		}
		// Load may reject unavailable kTLS before descriptor validation. Either
		// actual constructor failure must preserve cleanup uncertainty; this is
		// not evidence of successful offload or a particular host kernel module.
		if raw.closes.Load() != 1 || provider.closes.Load() != 1 {
			t.Fatal("kTLS failed construction not joined once")
		}
		var one [1]byte
		if n, err := peer.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("physical peer did not observe EOF: %d, %v", n, err)
		}
	}
}

type runtimeFailureHook struct {
	*runtimeTLSBarrier
	hook func() error
}

func (c *runtimeFailureHook) Close() error { return errors.Join(c.runtimeTLSBarrier.Close(), c.hook()) }

func TestRuntimeTLSFailureRawErrorAndReentrantRequest(t *testing.T) {
	for _, fail := range []bool{false, true} {
		raw := newRuntimeFailureRaw()
		var outer *outbound.RuntimeIOFence
		hook := &runtimeFailureHook{runtimeTLSBarrier: raw, hook: func() error {
			if fail {
				return errors.New("actual raw close failure")
			}
			if !errors.Is(outer.Close(), outbound.ErrRuntimeClosePending) {
				t.Error("reentrant request was not pending")
			}
			return nil
		}}
		guarded, inner := outbound.WrapRuntimeOwnedConn(hook)
		transport := &runtimeHandshakeConn{Conn: guarded, fence: inner}
		provider := &runtimeFailureProvider{Conn: transport}
		_, outer = outbound.WrapRuntimeOwnedConn(runtimeProviderCloseConn(provider, transport))
		done := make(chan error, 1)
		go func() { done <- outer.RuntimeCloseAndWait() }()
		var err error
		select {
		case err = <-done:
		case <-time.After(time.Second):
			t.Fatal("reentrant close request self-joined")
		}
		if fail {
			if !IsRuntimeCleanupIncomplete(err) {
				t.Fatal("actual raw close error disappeared")
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if raw.closes.Load() != 1 || provider.closes.Load() != 1 {
			t.Fatal("reentrant physical close repeated")
		}
	}
}
