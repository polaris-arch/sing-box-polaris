package hysteria2

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	M "github.com/sagernet/sing/common/metadata"
)

type outboundTestClient struct{ close func() error }

func (c outboundTestClient) RuntimeCloseAndWait() error {
	if c.close != nil {
		return c.close()
	}
	return nil
}

type outboundTestDialer struct {
	dial func(context.Context) (net.Conn, error)
}

func (d outboundTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx)
}

func (d outboundTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet listener")
}

type outboundTestConn struct {
	close func() error
	once  sync.Once
	err   error
}

func (c *outboundTestConn) Close() error {
	c.once.Do(func() {
		if c.close != nil {
			c.err = c.close()
		}
	})
	return c.err
}
func (*outboundTestConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*outboundTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*outboundTestConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*outboundTestConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*outboundTestConn) SetDeadline(time.Time) error      { return nil }
func (*outboundTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*outboundTestConn) SetWriteDeadline(time.Time) error { return nil }
func outboundTestWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("ownership barrier did not complete")
	}
}

func TestOutboundRejectsSealedReceiverBeforeClientAccess(t *testing.T) {
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "quic-node", Sequence: 1}, nil, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	owner.Seal()
	h := &Outbound{runtime: &outboundRuntime{source: owner}}
	// A dispatched call would touch the deliberately absent logger/client.
	if _, err = h.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil {
		t.Fatal("sealed receiver dispatched")
	}
	if _, err = h.ListenPacket(context.Background(), M.Socksaddr{}); err == nil {
		t.Fatal("sealed UDP receiver dispatched")
	}
}

func TestOutboundRuntimeRejectsUnjoinedLegacyClient(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	defer r.close()
	if err := r.install(context.Background(), struct{}{}); err == nil {
		t.Fatal("missing native worker join accepted")
	}
}

func TestOutboundLateSocketIsJoinedBeforeTerminalCleanup(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	if err := r.install(context.Background(), outboundTestClient{}); err != nil {
		t.Fatal(err)
	}
	entered, returnSocket, closeEntered, closeRelease := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var returnOnce, releaseOnce sync.Once
	returnNow := func() { returnOnce.Do(func() { close(returnSocket) }) }
	releaseNow := func() { releaseOnce.Do(func() { close(closeRelease) }) }
	t.Cleanup(returnNow)
	t.Cleanup(releaseNow)
	raw := &outboundTestConn{close: func() error { close(closeEntered); <-closeRelease; return nil }}
	dialer := r.guardDialer(outboundTestDialer{dial: func(context.Context) (net.Conn, error) { close(entered); <-returnSocket; return raw, nil }})
	dialDone := make(chan struct{})
	go func() { _, _ = dialer.DialContext(context.Background(), "udp", M.Socksaddr{}); close(dialDone) }()
	outboundTestWait(t, entered)
	closed := make(chan struct{})
	go func() { _ = r.close(); close(closed) }()
	outboundTestWait(t, r.ctx.Done())
	returnNow()
	outboundTestWait(t, closeEntered)
	select {
	case <-closed:
		t.Fatal("late socket close tail lost")
	default:
	}
	releaseNow()
	outboundTestWait(t, dialDone)
	outboundTestWait(t, closed)
}

func TestOutboundJoinedSocketPreservesTerminalCloseFailure(t *testing.T) {
	failure := errors.New("socket close incomplete")
	raw := &outboundTestConn{close: func() error { return failure }}
	guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
	conn := &outboundJoinedConn{Conn: guarded, fence: fence}
	if err := conn.Close(); err == nil {
		t.Fatal("close uncertainty lost")
	}
	if err := conn.Close(); err == nil {
		t.Fatal("close uncertainty not sticky")
	}
}

func TestOldOutboundCarrierSurvivesEditAndNewOwnerIsIndependent(t *testing.T) {
	var oldClosed, newClosed atomic.Bool
	old, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "quic-node", Sequence: 1}, nil, func() error { oldClosed.Store(true); return nil })
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "quic-node", Sequence: 2}, nil, func() error { newClosed.Store(true); return nil })
	if err != nil {
		t.Fatal(err)
	}
	conn, err := outbound.DialRuntimeConn(context.Background(), old, func(context.Context) (net.Conn, error) { return &outboundTestConn{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	old.Seal() // node edit/remove retires only old root admission
	if oldClosed.Load() {
		t.Fatal("editing node destroyed admitted old carrier")
	}
	if _, err = conn.Write([]byte("old TLS/auth generation")); err != nil {
		t.Fatal(err)
	}
	next, err := outbound.DialRuntimeConn(context.Background(), fresh, func(context.Context) (net.Conn, error) { return &outboundTestConn{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	fresh.Seal()
	if newClosed.Load() {
		t.Fatal("new generation lost its carrier")
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = old.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
	if newClosed.Load() {
		t.Fatal("old close affected new generation")
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
	if err = fresh.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
}

type outboundDescriptorConn struct {
	outboundTestConn
	calls atomic.Int32
}

func (c *outboundDescriptorConn) SyscallConn() (syscall.RawConn, error) {
	c.calls.Add(1)
	return nil, errors.New("descriptor probe")
}

func TestObfuscationCarrierCannotExposeUnderlyingDescriptor(t *testing.T) {
	raw := &outboundDescriptorConn{}
	r := newOutboundRuntime(context.Background())
	defer r.close()
	opaque := r.nativeCarrier(raw)
	guarded, fence := outbound.WrapRuntimeOwnedConn(opaque)
	defer fence.RuntimeCloseAndWait()
	_, _ = outbound.RuntimeSyscallConn(guarded)
	if raw.calls.Load() != 0 {
		t.Fatal("native fast path bypassed obfuscation/hopping")
	}
	r.allowNativeDescriptor = true
	plain := r.nativeCarrier(raw)
	guardedPlain, plainFence := outbound.WrapRuntimeOwnedConn(plain)
	defer plainFence.RuntimeCloseAndWait()
	_, _ = outbound.RuntimeSyscallConn(guardedPlain)
	if raw.calls.Load() != 1 {
		t.Fatal("plain UDP lost guarded descriptor path")
	}
}
