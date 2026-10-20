package proxybridge

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

type (
	bridgeTestSource struct {
		mu   sync.Mutex
		refs int
	}
	bridgeTestLease struct {
		source   *bridgeTestSource
		released bool
	}
)

func (*bridgeTestSource) ID() adapter.RuntimeResourceID {
	return adapter.RuntimeResourceID{Incarnation: "bridge-test", Sequence: 1}
}

func (*bridgeTestSource) RetainCapturedResource(adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	return nil, errors.New("no captured dependencies")
}

func (s *bridgeTestSource) Acquire() (adapter.RuntimeResourceLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs++
	return &bridgeTestLease{source: s}, nil
}
func (l *bridgeTestLease) ID() adapter.RuntimeResourceID { return l.source.ID() }
func (*bridgeTestLease) Retiring() <-chan struct{}       { return nil }
func (l *bridgeTestLease) Fork() (adapter.RuntimeResourceLease, error) {
	l.source.mu.Lock()
	defer l.source.mu.Unlock()
	if l.released {
		return nil, net.ErrClosed
	}
	l.source.refs++
	return &bridgeTestLease{source: l.source}, nil
}

func (l *bridgeTestLease) Release() {
	l.source.mu.Lock()
	defer l.source.mu.Unlock()
	if !l.released {
		l.released = true
		l.source.refs--
	}
}

type bridgeTestDialer struct {
	entered chan context.Context
	proceed chan struct{}
	raw     *bridgeTestConn
}

func (d *bridgeTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.entered <- ctx
	<-d.proceed
	return d.raw, nil
}

func (*bridgeTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type bridgeTestConn struct {
	closes   atomic.Int32
	closeErr error
}

func (*bridgeTestConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*bridgeTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *bridgeTestConn) Close() error                   { c.closes.Add(1); return c.closeErr }
func (*bridgeTestConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*bridgeTestConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*bridgeTestConn) SetDeadline(time.Time) error      { return nil }
func (*bridgeTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*bridgeTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestInternalBridgeDoesNotInheritBorrowedCreationHandles(t *testing.T) {
	source := &bridgeTestSource{}
	lease, _ := source.Acquire()
	type ordinaryKey struct{}
	ctx := context.WithValue(context.Background(), ordinaryKey{}, "kept")
	ctx = adapter.ContextWithRuntimeResourceSource(adapter.ContextWithRuntimeResourceLease(ctx, lease), source)
	b, err := New(ctx, log.NewNOPFactory().Logger(), "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := adapter.RuntimeResourceLeaseFromContext(b.ctx, source.ID()); ok {
		t.Fatal("internal copy inherited borrowed owner lease")
	}
	if b.ctx.Value(ordinaryKey{}) != "kept" {
		t.Fatal("ordinary values lost")
	}
	lease.Release()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInternalBridgeLateDialAndFailedClose(t *testing.T) {
	for _, closeErr := range []error{nil, context.Canceled} {
		source := &bridgeTestSource{}
		raw := &bridgeTestConn{closeErr: closeErr}
		dialer := &bridgeTestDialer{entered: make(chan context.Context), proceed: make(chan struct{}), raw: raw}
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
		ctx := adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), source)
		ownerFence := outbound.NewRuntimeIOFence(nil)
		admit, err := outbound.RegisterRuntimeOwnedFence(ctx, ownerFence)
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewWithRuntimeContinuation(ctx, log.NewNOPFactory().Logger(), "test", dialer, admit)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			conn, err := (&ownedDialer{bridge: b}).DialContext(b.ctx, "tcp", M.Socksaddr{})
			if conn != nil {
				result <- errors.New("published late conn")
				return
			}
			result <- err
		}()
		physical := <-dialer.entered
		closed := make(chan error, 1)
		go func() { closed <- b.Close() }()
		<-physical.Done()
		close(dialer.proceed)
		if err := <-result; err == nil {
			t.Fatal("late physical conn published")
		}
		err = <-closed
		if closeErr == nil && err != nil {
			t.Fatal(err)
		}
		if closeErr != nil && (err == nil || errors.Is(err, context.Canceled)) {
			t.Fatal("close failure lost uncertainty")
		}
		if raw.closes.Load() != 1 {
			t.Fatal("raw close not sole owned operation")
		}
		if err := ownerFence.RuntimeCloseAndWait(); err != nil {
			t.Fatal(err)
		}
		if source.refs != 0 {
			t.Fatal("owned bridge dial pinned its own resource")
		}
		_ = scope.Close()
	}
}

func TestInternalBridgeCallbackTailJoinsBeforeCleanup(t *testing.T) {
	b, err := New(context.Background(), log.NewNOPFactory().Logger(), "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	entered, proceed := make(chan struct{}), make(chan struct{})
	callback := b.guardOnClose(func(error) { close(entered); <-proceed })
	done := make(chan struct{})
	go func() { callback(nil); close(done) }()
	<-entered
	_ = b.handlers.Close()
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	select {
	case <-closed:
		t.Fatal("in-flight callback was released")
	default:
	}
	close(proceed)
	<-done
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	// A copied callback invoked after seal is inert.
	callback(nil)
}
