//go:build with_naive_outbound

package naive

import (
 "context"
 "errors"
 "net"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/sagernet/cronet-go"
 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/internal/runtimegraph"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
 mDNS "github.com/miekg/dns"
)

type naiveOutboundTestCloser struct { close func() error }
func (c naiveOutboundTestCloser) Close() error { if c.close != nil { return c.close() }; return nil }
type naiveOutboundTestDialer struct { dial func(context.Context) (net.Conn, error) }
func (d naiveOutboundTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) { return d.dial(ctx) }
func (d naiveOutboundTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) { return nil, errors.New("unexpected unconnected dial") }
type naiveOutboundTestConn struct { close func() error; once sync.Once; err error; halfClosed atomic.Bool }
func (c *naiveOutboundTestConn) Close() error { c.once.Do(func() { if c.close != nil { c.err = c.close() } }); return c.err }
func (*naiveOutboundTestConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (*naiveOutboundTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (*naiveOutboundTestConn) LocalAddr() net.Addr { return &net.TCPAddr{} }
func (*naiveOutboundTestConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (*naiveOutboundTestConn) SetDeadline(time.Time) error { return nil }
func (*naiveOutboundTestConn) SetReadDeadline(time.Time) error { return nil }
func (*naiveOutboundTestConn) SetWriteDeadline(time.Time) error { return nil }
func (*naiveOutboundTestConn) Upstream() any { return &net.TCPConn{} }
func (c *naiveOutboundTestConn) CloseWrite() error { c.halfClosed.Store(true); return nil }
func naiveOutboundWait(t *testing.T, ch <-chan struct{}) { t.Helper(); select { case <-ch: case <-time.After(5*time.Second): t.Fatal("completion barrier did not finish") } }

func TestNaiveOutboundSealedReceiverAndClientAccessor(t *testing.T) {
 owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "naive", Sequence: 1}, nil, func() error { return nil })
 if err != nil { t.Fatal(err) }
 owner.Seal()
 client := &cronet.NaiveClient{}
 h := &Outbound{runtime: &outboundRuntime{source: owner}, client: client}
 if _, err := h.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil { t.Fatal("sealed receiver dispatched") }
 if _, err := h.ListenPacket(context.Background(), M.Socksaddr{}); err == nil { t.Fatal("sealed receiver dispatched") }
 if h.Client() != nil { t.Fatal("native client escaped runtime owner") }
 if (&Outbound{client: client}).Client() != client { t.Fatal("standalone accessor changed") }
}
func TestNaiveOutboundLateDialCompensatesBeforeClose(t *testing.T) {
 r := newOutboundRuntime(context.Background())
 r.client = naiveOutboundTestCloser{}
 if err := r.install(context.Background()); err != nil { t.Fatal(err) }
 entered, returned, closeEntered, closeRelease := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
 var returnOnce, releaseOnce sync.Once
 releaseDial := func() { returnOnce.Do(func() { close(returned) }) }
 releaseClose := func() { releaseOnce.Do(func() { close(closeRelease) }) }
 t.Cleanup(releaseDial); t.Cleanup(releaseClose)
 raw := &naiveOutboundTestConn{close: func() error { close(closeEntered); <-closeRelease; return nil }}
 d := r.guardDialer(naiveOutboundTestDialer{dial: func(context.Context) (net.Conn, error) { close(entered); <-returned; return raw, nil }})
 dialDone := make(chan struct{})
 go func() { _, _ = d.DialContext(context.Background(), "tcp", M.Socksaddr{}); close(dialDone) }()
 naiveOutboundWait(t, entered)
 closed := make(chan struct{})
 go func() { _ = r.close(); close(closed) }()
 naiveOutboundWait(t, r.ctx.Done()); releaseDial(); naiveOutboundWait(t, closeEntered)
 select { case <-closed: t.Fatal("late socket cleanup lost"); default: }
 releaseClose(); naiveOutboundWait(t, dialDone); naiveOutboundWait(t, closed)
}
func TestNaiveOutboundPhysicalCarrierUsesRelayAndHalfClose(t *testing.T) {
 r := newOutboundRuntime(context.Background()); defer r.close()
 r.client = naiveOutboundTestCloser{}
 if err := r.install(context.Background()); err != nil { t.Fatal(err) }
 raw := &naiveOutboundTestConn{}
 d := r.guardDialer(naiveOutboundTestDialer{dial: func(context.Context) (net.Conn, error) { return raw, nil }})
 conn, err := d.DialContext(context.Background(), "tcp", M.Socksaddr{})
 if err != nil { t.Fatal(err) }
 if _, ok := N.CastReader[*net.TCPConn](conn); ok { t.Fatal("raw TCP socket escaped and bypassed relay") }
 if _, ok := N.CastReader[*net.UDPConn](conn); ok { t.Fatal("raw UDP socket escaped and bypassed relay") }
 if err := conn.(interface { CloseWrite() error }).CloseWrite(); err != nil { t.Fatal(err) }
 if !raw.halfClosed.Load() { t.Fatal("relay half close not preserved") }
 if err := conn.Close(); err != nil { t.Fatal(err) }
}
func TestNaiveOutboundNativeFailureRemainsSticky(t *testing.T) {
 r := newOutboundRuntime(context.Background())
 var calls atomic.Int32
 r.client = naiveOutboundTestCloser{close: func() error { calls.Add(1); return errors.New("native shutdown incomplete") }}
 if err := r.install(context.Background()); err != nil { t.Fatal(err) }
 if r.close() == nil || r.close() == nil { t.Fatal("native close uncertainty disappeared") }
 if calls.Load() != 1 { t.Fatal("native terminal close repeated") }
}
func TestNaiveOutboundDNSCallbackRejectedAfterClose(t *testing.T) {
 r := newOutboundRuntime(context.Background())
 // Bind callback admission to a real fence even without a native engine.
 r.begin = func(ctx context.Context) (context.Context, func(), error) { leave, err := r.fence.Acquire(); return ctx, leave, err }
 var calls atomic.Int32
 resolve := r.guardDNS(func(_ context.Context, request *mDNS.Msg) *mDNS.Msg { calls.Add(1); return request })
 if err := r.close(); err != nil { t.Fatal(err) }
 response := resolve(context.Background(), new(mDNS.Msg))
 if calls.Load() != 0 || response.Rcode != mDNS.RcodeServerFailure { t.Fatal("sealed DNS callback dispatched") }
}

func TestNaiveOutboundCloseJoinsNativeCompletion(t *testing.T) {
 r := newOutboundRuntime(context.Background())
 entered, release := make(chan struct{}), make(chan struct{})
 var once sync.Once
 releaseNative := func() { once.Do(func() { close(release) }) }
 t.Cleanup(releaseNative)
 r.client = naiveOutboundTestCloser{close: func() error { close(entered); <-release; return nil }}
 if err := r.install(context.Background()); err != nil { t.Fatal(err) }
 closed := make(chan struct{})
 go func() { _ = r.close(); close(closed) }()
 naiveOutboundWait(t, entered)
 select { case <-closed: t.Fatal("native completion was not joined"); default: }
 releaseNative(); naiveOutboundWait(t, closed)
}

func TestNaiveStandaloneClientOptionsKeepNativePaths(t *testing.T) {
 ctx := context.WithValue(context.Background(), struct{}{}, "standalone")
 r := newOutboundRuntime(ctx)
 dialer := &naiveOutboundTestDialer{}
 request := new(mDNS.Msg)
 var calls atomic.Int32
 options := cronet.NaiveClientOptions{
  Context: ctx,
  Dialer: dialer,
  DNSResolver: func(_ context.Context, got *mDNS.Msg) *mDNS.Msg { calls.Add(1); return got },
 }
 guarded := r.guardClientOptions(options)
 if guarded.Context != ctx || guarded.Dialer != dialer || guarded.Logger != options.Logger { t.Fatal("standalone native inputs changed") }
 if err := r.close(); err != nil { t.Fatal(err) }
 if guarded.DNSResolver(ctx, request) != request || calls.Load() != 1 { t.Fatal("standalone DNS callback was wrapped") }
}
