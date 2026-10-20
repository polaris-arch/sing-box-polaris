package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	mDNS "github.com/miekg/dns"
)

func runtimeTransportAwait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select { case <-done: case <-time.After(5*time.Second): t.Fatal("actual transport completion barrier timed out") }
}
func runtimeTransportPending(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select { case <-done: t.Fatal("transport completion published before actual return"); default: }
}
type runtimeOwnedConn struct {
	net.Conn
	closed chan struct{}
	once sync.Once
	kind string
	closes atomic.Int32
}
func newRuntimeOwnedConn(kind string) *runtimeOwnedConn { return &runtimeOwnedConn{closed: make(chan struct{}), kind: kind} }
func (c *runtimeOwnedConn) Close() error { c.once.Do(func() { c.closes.Add(1); close(c.closed) }); return nil }
// Observe only the fixture identity through the production wrappers. All I/O
// and Close still use the wrapped connection so cleanup ownership is exercised.
func runtimeFixtureConn(conn net.Conn) *runtimeOwnedConn {
 if multiplexed,ok:=conn.(*multiplexConn);ok { conn=multiplexed.Conn }
 return conn.(*runtimeDNSCloseConn).Conn.(*runtimeOwnedConn)
}

func runtimeQuery() *mDNS.Msg { query := new(mDNS.Msg); query.SetQuestion("runtime.example.", mDNS.TypeA); return query }

func TestMultiplexerRetirementCancelsProbeButKeepsAdmittedSingle(t *testing.T) {
	probeEntered, singleEntered := make(chan struct{}), make(chan struct{})
	probeRelease, singleRelease := make(chan struct{}), make(chan struct{})
	probeCanceled, singleCanceled := make(chan struct{}), make(chan struct{})
	returned := make(chan struct{})
	var probeOnce, singleOnce sync.Once
	multiplexer := newQueryMultiplexer(queryMultiplexerOptions{
		probeReuse: true,
		dial: func(ctx context.Context) (net.Conn, error) {
			kind := "single"
			if _, hasDeadline := ctx.Deadline(); hasDeadline { kind = "probe" }
			conn := newRuntimeOwnedConn(kind)
			if kind == "probe" { go func() { <-ctx.Done(); close(probeCanceled) }() } else { go func() { <-ctx.Done(); close(singleCanceled) }() }
			return conn, nil
		},
		write: func(net.Conn, *mDNS.Msg, uint16) error { return nil },
		readNext: func(conn net.Conn) (*mDNS.Msg, error) {
			if runtimeFixtureConn(conn).kind == "probe" { close(probeEntered); <-probeRelease } else { close(singleEntered); <-singleRelease }
			return nil, io.EOF
		},
	})
	t.Cleanup(func() {
		probeOnce.Do(func() { close(probeRelease) }); singleOnce.Do(func() { close(singleRelease) })
		multiplexer.Stop(); runtimeTransportAwait(t, returned); runtimeTransportAwait(t, multiplexer.closeDone)
		runtimeTransportAwait(t, probeCanceled); runtimeTransportAwait(t, singleCanceled)
	})
	multiplexer.ExchangeAsync(context.Background(), runtimeQuery(), func(*mDNS.Msg, error) { close(returned) })
	runtimeTransportAwait(t, probeEntered); runtimeTransportAwait(t, singleEntered)
	multiplexer.StopProbes()
	runtimeTransportAwait(t, probeCanceled)
	runtimeTransportPending(t, singleCanceled)
	multiplexer.Stop()
	runtimeTransportAwait(t, singleCanceled)
	runtimeTransportPending(t, multiplexer.closeDone)
	probeOnce.Do(func() { close(probeRelease) })
	runtimeTransportPending(t, multiplexer.closeDone)
	singleOnce.Do(func() { close(singleRelease) })
	runtimeTransportAwait(t, returned); runtimeTransportAwait(t, multiplexer.closeDone)
	if err := multiplexer.Close(); err != nil { t.Fatal(err) }
}

func TestMultiplexerCloseJoinsIdleRecvLoopWithoutExternalSelfLease(t *testing.T) {
	conn := newRuntimeOwnedConn("pool")
	written := make(chan uint16, 1)
	recvIdle := make(chan struct{})
	var reads atomic.Int32
	multiplexer := newQueryMultiplexer(queryMultiplexerOptions{
		dial: func(context.Context) (net.Conn, error) { return conn, nil },
		write: func(_ net.Conn, _ *mDNS.Msg, id uint16) error { written <- id; return nil },
		readNext: func(net.Conn) (*mDNS.Msg, error) {
			if reads.Add(1) == 1 { var id uint16; select { case id = <-written: case <-conn.closed: return nil, io.EOF }; response := new(mDNS.Msg); response.Id = id; return response, nil }
			close(recvIdle); <-conn.closed; return nil, io.EOF
		},
	})
	callReturned := make(chan struct{})
	var exchangeErr error
	t.Cleanup(func() { multiplexer.Stop(); runtimeTransportAwait(t, callReturned); runtimeTransportAwait(t, multiplexer.closeDone) })
	go func() { defer close(callReturned); _, exchangeErr = multiplexer.Exchange(context.Background(), runtimeQuery()) }()
	runtimeTransportAwait(t, callReturned)
	if exchangeErr != nil { t.Fatal(exchangeErr) }
	runtimeTransportAwait(t, recvIdle)
	multiplexer.Stop()
	runtimeTransportAwait(t, conn.closed); runtimeTransportAwait(t, multiplexer.closeDone)
	if conn.closes.Load() != 1 { t.Fatal("connection not closed exactly once") }
}

func TestMultiplexerAfterFuncCompletionAndReentrantStop(t *testing.T) {
	multiplexer := newQueryMultiplexer(queryMultiplexerOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { cancel(); once.Do(func() { close(release) }); multiplexer.Stop(); runtimeTransportAwait(t, multiplexer.closeDone) })
	stop, admitted := multiplexer.afterFunc(ctx, func() { multiplexer.Stop(); close(entered); <-release })
	if !admitted { t.Fatal("callback not admitted") }
	cancel(); runtimeTransportAwait(t, entered)
	if stop() { t.Fatal("running callback reported canceled-before-start") }
	runtimeTransportPending(t, multiplexer.closeDone)
	once.Do(func() { close(release) }); runtimeTransportAwait(t, multiplexer.closeDone)
	if err := multiplexer.Close(); err != nil { t.Fatal(err) }
	if _, admitted := multiplexer.afterFunc(context.Background(), func() { t.Error("post-close callback") }); admitted { t.Fatal("callback scheduling resurrected") }
}

func TestMultiplexerCloseJoinsCanceledPoolDialTail(t *testing.T) {
	dialEntered, dialRelease := make(chan struct{}), make(chan struct{})
	callbackReturned := make(chan struct{})
	conn := newRuntimeOwnedConn("late-dial")
	var once sync.Once
	multiplexer := newQueryMultiplexer(queryMultiplexerOptions{
		dial: func(context.Context) (net.Conn, error) { close(dialEntered); <-dialRelease; return conn, nil },
		write: func(net.Conn, *mDNS.Msg, uint16) error { return nil },
		readNext: func(net.Conn) (*mDNS.Msg, error) { return nil, io.EOF },
	})
	ctx, cancel := context.WithCancel(context.Background())
	callReturned := make(chan struct{})
	t.Cleanup(func() { cancel(); once.Do(func() { close(dialRelease) }); multiplexer.Stop(); runtimeTransportAwait(t, callReturned); runtimeTransportAwait(t, multiplexer.closeDone) })
	go func() { defer close(callReturned); multiplexer.ExchangeAsync(ctx, runtimeQuery(), func(*mDNS.Msg, error) { close(callbackReturned) }) }()
	runtimeTransportAwait(t, dialEntered)
	cancel(); runtimeTransportAwait(t, callbackReturned); runtimeTransportAwait(t, callReturned)
	multiplexer.Stop(); runtimeTransportPending(t, multiplexer.closeDone)
	once.Do(func() { close(dialRelease) })
	runtimeTransportAwait(t, conn.closed); runtimeTransportAwait(t, multiplexer.closeDone)
}

func TestTransportOwnerClosesAfterRealCallbackAndWorkerTail(t *testing.T) {
	var transport *TCPTransport
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "transport-run", Sequence: 1}, nil, func() error { return transport.multiplexer.Close() })
	if err != nil { t.Fatal(err) }
	construction, err := owner.Acquire()
	if err != nil { t.Fatal(err) }
	ctx := adapter.ContextWithRuntimeResourceSource(owner.Context(), owner)
	transport = newTCPRaw(ctx, boxDNS.NewTransportAdapter("tcp", "owned", nil), nil, M.Socksaddr{})
	// The actual transport/multiplexer paths run, with only socket IO replaced.
	transport.multiplexer.options.probeReuse = false
	conn := newRuntimeOwnedConn("owner")
	written := make(chan uint16, 1)
	readRelease, callbackEntered, callbackRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var readOnce, callbackOnce sync.Once
	transport.multiplexer.options.dial = func(context.Context) (net.Conn, error) { return transport.multiplexer.trackClose(conn), nil }
	transport.multiplexer.options.write = func(_ net.Conn, _ *mDNS.Msg, id uint16) error { written <- id; return nil }
	var reads atomic.Int32
	transport.multiplexer.options.readNext = func(net.Conn) (*mDNS.Msg, error) {
		if reads.Add(1) == 1 { var id uint16; select { case id = <-written: case <-conn.closed: return nil, io.EOF }; <-readRelease; response := new(mDNS.Msg); response.Id = id; return response, nil }
		<-conn.closed; return nil, io.EOF
	}
	callbackReturned, callReturned := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		readOnce.Do(func() { close(readRelease) }); callbackOnce.Do(func() { close(callbackRelease) })
		owner.Seal(); construction.Release(); transport.StopRuntimeOperations(); runtimeTransportAwait(t, callReturned); runtimeTransportAwait(t, callbackReturned); runtimeTransportAwait(t, owner.Closed())
	})
	go func() { defer close(callReturned); transport.ExchangeAsync(context.Background(), runtimeQuery(), func(*mDNS.Msg, error) { close(callbackEntered); <-callbackRelease; close(callbackReturned) }) }()
	runtimeTransportAwait(t, callReturned)
	owner.Seal(); construction.Release(); transport.StopRuntimeProducers()
	readOnce.Do(func() { close(readRelease) }); runtimeTransportAwait(t, callbackEntered)
	runtimeTransportPending(t, owner.Closed())
	callbackOnce.Do(func() { close(callbackRelease) })
	runtimeTransportAwait(t, callbackReturned); runtimeTransportAwait(t, owner.Closed())
	if err := owner.WaitClosed(context.Background()); err != nil { t.Fatal(err) }
	if _, err := transport.Exchange(context.Background(), runtimeQuery()); !errors.Is(err, runtimegraph.ErrResourceSealed) { t.Fatalf("stale transport root admitted: %v", err) }
}

func TestOwnedTransportConstructorCleanupBeforeAndAfterStart(t *testing.T) {
	constructors := map[string]func(context.Context, log.ContextLogger, string, option.RemoteDNSServerOptions) (adapter.DNSTransport, error){"tcp": NewTCP, "udp": NewUDP}
	for kind, constructor := range constructors {
		for _, start := range []bool{false, true} {
			name := kind + "/before-start"
			if start { name = kind + "/after-start" }
			t.Run(name, func(t *testing.T) {
				logger := log.NewNOPFactory().Logger()
				var scope *adapter.Scope
				owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "constructor", Sequence: 1}, nil, func() error { return scope.Close() })
				if err != nil { t.Fatal(err) }
				construction, err := owner.Acquire()
				if err != nil { t.Fatal(err) }
				scope = adapter.NewScope(owner.Context(), logger)
				ctx := adapter.ContextWithRuntimeResourceSource(scope.Context(), owner)
				ctx = adapter.ContextWithConstructionScope(ctx, scope)
				t.Cleanup(func() { owner.Seal(); construction.Release(); runtimeTransportAwait(t, owner.Closed()) })
				transport, err := constructor(ctx, logger, kind, option.RemoteDNSServerOptions{DNSServerAddressOptions: option.DNSServerAddressOptions{Server: "192.0.2.53"}})
				if err != nil { t.Fatal(err) }
				var multiplexer *queryMultiplexer
				switch transport := transport.(type) {
				case *TCPTransport:
					if transport.runtimeResource != owner || !transport.constructionOwned { t.Fatal("TCP constructor owner missing") }
					multiplexer = transport.multiplexer
				case *UDPTransport:
					if transport.runtimeResource != owner || !transport.constructionOwned { t.Fatal("UDP constructor owner missing") }
					multiplexer = transport.multiplexer
				default: t.Fatal("unexpected transport type")
				}
				if start { if err := scope.Start(kind, transport, adapter.StartStateStart); err != nil { t.Fatal(err) } }
				owner.Seal(); construction.Release(); runtimeTransportAwait(t, owner.Closed())
				runtimeTransportAwait(t, multiplexer.closeDone)
				if err := owner.WaitClosed(context.Background()); err != nil { t.Fatal(err) }
				if err := multiplexer.Close(); err != nil { t.Fatal(err) }
			})
		}
	}
}

func TestTransportRetryKeepsOriginalOwnerUntilSuccessorCallback(t *testing.T) {
	var transport *TCPTransport
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "retry-run", Sequence: 1}, nil, func() error { return transport.multiplexer.Close() })
	if err != nil { t.Fatal(err) }
	construction, err := owner.Acquire()
	if err != nil { t.Fatal(err) }
	transport = newTCPRaw(adapter.ContextWithRuntimeResourceSource(owner.Context(), owner), boxDNS.NewTransportAdapter("tcp", "retry", nil), nil, M.Socksaddr{})
	transport.multiplexer.options.probeReuse = false
	first, second := newRuntimeOwnedConn("first"), newRuntimeOwnedConn("second")
	writesFirst, writesSecond := make(chan uint16, 2), make(chan uint16, 1)
	retryEntered, retryRelease := make(chan struct{}), make(chan struct{})
	callbackEntered, callbackRelease, callbackReturned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var retryOnce, callbackOnce sync.Once
	var dials, readsFirst, readsSecond atomic.Int32
	transport.multiplexer.options.dial = func(context.Context) (net.Conn, error) {
		if dials.Add(1) == 1 { return transport.multiplexer.trackClose(first), nil }
		close(retryEntered); <-retryRelease; return transport.multiplexer.trackClose(second), nil
	}
	transport.multiplexer.options.write = func(conn net.Conn, _ *mDNS.Msg, id uint16) error {
		if runtimeFixtureConn(conn) == first { writesFirst <- id } else { writesSecond <- id }
		return nil
	}
	transport.multiplexer.options.readNext = func(conn net.Conn) (*mDNS.Msg, error) {
		if runtimeFixtureConn(conn) == first {
			if readsFirst.Add(1) == 1 { var id uint16; select { case id = <-writesFirst: case <-first.closed: return nil, io.EOF }; response := new(mDNS.Msg); response.Id = id; return response, nil }
			select { case <-writesFirst: case <-first.closed: }; return nil, io.EOF
		}
		if readsSecond.Add(1) == 1 { var id uint16; select { case id = <-writesSecond: case <-second.closed: return nil, io.EOF }; response := new(mDNS.Msg); response.Id = id; return response, nil }
		<-second.closed; return nil, io.EOF
	}
	firstReturned, callReturned := make(chan struct{}), make(chan struct{})
	var firstErr, callbackErr error
	var secondStarted bool
	t.Cleanup(func() {
		retryOnce.Do(func() { close(retryRelease) }); callbackOnce.Do(func() { close(callbackRelease) })
		owner.Seal(); construction.Release(); transport.StopRuntimeOperations(); runtimeTransportAwait(t, firstReturned)
		if secondStarted { runtimeTransportAwait(t, callReturned); runtimeTransportAwait(t, callbackReturned) }
		runtimeTransportAwait(t, owner.Closed())
	})
	go func() { defer close(firstReturned); _, firstErr = transport.Exchange(context.Background(), runtimeQuery()) }()
	runtimeTransportAwait(t, firstReturned)
	if firstErr != nil { t.Fatal(firstErr) }
	secondStarted = true
	go func() { defer close(callReturned); transport.ExchangeAsync(context.Background(), runtimeQuery(), func(_ *mDNS.Msg, err error) { callbackErr = err; close(callbackEntered); <-callbackRelease; close(callbackReturned) }) }()
	runtimeTransportAwait(t, retryEntered)
	owner.Seal(); construction.Release(); runtimeTransportPending(t, owner.Closed())
	retryOnce.Do(func() { close(retryRelease) }); runtimeTransportAwait(t, callbackEntered)
	runtimeTransportPending(t, owner.Closed())
	callbackOnce.Do(func() { close(callbackRelease) }); runtimeTransportAwait(t, callbackReturned); runtimeTransportAwait(t, owner.Closed())
	if callbackErr != nil { t.Fatal(callbackErr) }
	if dials.Load() != 2 { t.Fatal("retry did not use the reserved successor") }
}


type runtimeMissingOutboundManager struct { adapter.OutboundManager }
func (*runtimeMissingOutboundManager) Outbound(string) (adapter.Outbound, bool) { return nil, false }

func TestOwnedTransportStartFailureAndMissingScopeCloseAllocatedWorkers(t *testing.T) {
	constructors := map[string]func(context.Context, log.ContextLogger, string, option.RemoteDNSServerOptions) (adapter.DNSTransport, error){"tcp": NewTCP, "udp": NewUDP}
	for kind, constructor := range constructors {
		t.Run(kind, func(t *testing.T) {
			logger := log.NewNOPFactory().Logger()
			var scope *adapter.Scope
			owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "failed-constructor", Sequence: 1}, nil, func() error { return scope.Close() })
			if err != nil { t.Fatal(err) }
			construction, err := owner.Acquire()
			if err != nil { t.Fatal(err) }
			scope = adapter.NewScope(owner.Context(), logger)
			ctx := adapter.ContextWithRuntimeResourceSource(scope.Context(), owner)
			options := option.RemoteDNSServerOptions{DNSServerAddressOptions: option.DNSServerAddressOptions{Server: "192.0.2.53"}}
			t.Cleanup(func() { owner.Seal(); construction.Release(); runtimeTransportAwait(t, owner.Closed()) })
			if result, err := constructor(ctx, logger, kind, options); !errors.Is(err, net.ErrClosed) || result != nil { t.Fatalf("missing construction scope escaped: %v %v", result, err) }
			ctx = service.ContextWithDefaultRegistry(adapter.ContextWithConstructionScope(ctx, scope))
			service.MustRegister[adapter.OutboundManager](ctx, &runtimeMissingOutboundManager{})
			options.Detour = "absent"
			transport, err := constructor(ctx, logger, kind, options)
			if err != nil { t.Fatal(err) }
			if err := scope.Start(kind, transport, adapter.StartStateStart); err == nil { t.Fatal("missing detour unexpectedly started") }
			var multiplexer *queryMultiplexer
			switch transport := transport.(type) { case *TCPTransport: multiplexer = transport.multiplexer; case *UDPTransport: multiplexer = transport.multiplexer; default: t.Fatal("unexpected transport type") }
			owner.Seal(); construction.Release(); runtimeTransportAwait(t, owner.Closed()); runtimeTransportAwait(t, multiplexer.closeDone)
			if err := owner.WaitClosed(context.Background()); err != nil { t.Fatal(err) }
		})
	}
}


func TestMultiplexerClosePanicRemainsStickyUncertainty(t *testing.T) {
	conn := newRuntimeOwnedConn("panic-close")
	multiplexer := newQueryMultiplexer(queryMultiplexerOptions{dial: func(context.Context) (net.Conn, error) { return conn, nil }})
	// Install one real pool connection without starting a read worker; only its
	// cleanup boundary is under test, and the panic must not escape Stop's worker.
	if _, _, _, err := multiplexer.connection.AcquireShared(context.Background(), multiplexer.dialConn); err != nil { t.Fatal(err) }
	multiplexer.connection.options.Close = func(*multiplexConn, error) { conn.Close(); panic("close failure") }
	t.Cleanup(func() { multiplexer.Stop(); runtimeTransportAwait(t, multiplexer.closeDone) })
	multiplexer.Stop(); runtimeTransportAwait(t, multiplexer.closeDone)
	first, second := multiplexer.Close(), multiplexer.Close()
	if first == nil || first != second { t.Fatalf("cleanup uncertainty was lost: %v %v", first, second) }
	runtimeTransportAwait(t, conn.closed)
}
