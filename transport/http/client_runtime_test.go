package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type runtimeTestDialer func(context.Context, string, M.Socksaddr) (net.Conn, error)

func (d runtimeTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, network, destination)
}

func (runtimeTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func waitHTTPBarrier(t *testing.T, barrier <-chan struct{}) {
	t.Helper()
	select {
	case <-barrier:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP test barrier was not reached")
	}
}

func assertHTTPPending(t *testing.T, barrier <-chan struct{}) {
	t.Helper()
	select {
	case <-barrier:
		t.Fatal("HTTP operation completed before its actual worker tail")
	default:
	}
}

func newRuntimeHTTPClient(t *testing.T, dialer runtimeTestDialer) (*Client, *runtimegraph.ResourceOwner) {
	t.Helper()
	var scope *adapter.Scope
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "http-test", Sequence: 1}, nil, func() error { return scope.Close() })
	if err != nil {
		t.Fatal(err)
	}
	scope = adapter.NewScope(owner.Context(), log.NewNOPFactory().Logger())
	ctx := adapter.ContextWithConstructionScope(owner.Context(), scope)
	ctx = adapter.ContextWithRuntimeResourceSource(ctx, owner)
	client, err := NewClientWithTLS(ctx, log.NewNOPFactory().Logger(), dialer, option.ServerOptions{Server: "192.0.2.1", ServerPort: 8080}, option.OutboundTLSOptions{}, ClientOptions{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	return client, owner
}

// The real constructor owns client cleanup before any lifecycle Start. A later
// constructor failure drains the same scope, including a never-started client.
func TestHTTPClientConstructorFailureBeforeStart(t *testing.T) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	ctx := adapter.ContextWithConstructionScope(context.Background(), scope)
	client, err := NewClientWithTLS(ctx, log.NewNOPFactory().Logger(), nil, option.ServerOptions{Server: "192.0.2.1", ServerPort: 8080}, option.OutboundTLSOptions{}, ClientOptions{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	laterConstructor := func() error { return errors.New("later constructor failed") }
	if laterConstructor() == nil {
		t.Fatal("expected constructor failure")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if !client.isClosed() {
		t.Fatal("unstarted constructor resource escaped rollback")
	}
	if _, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed constructor admitted work: %v", err)
	}
}

func TestHTTPClientCanceledConstructionScope(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	scope := adapter.NewScope(parent, log.NewNOPFactory().Logger())
	cancel()
	// Deliberately use a live outer context. The scope itself is canceled.
	ctx := adapter.ContextWithConstructionScope(context.Background(), scope)
	client, err := NewClientWithTLS(ctx, log.NewNOPFactory().Logger(), nil, option.ServerOptions{Server: "192.0.2.1", ServerPort: 8080}, option.OutboundTLSOptions{}, ClientOptions{Version: 1})
	if client != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scope returned a client: %v, %v", client, err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
}

type closeTailConn struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
	allow   chan struct{}
}

func (c *closeTailConn) Close() error {
	c.once.Do(func() {
		_ = c.Conn.Close()
		close(c.entered)
		<-c.allow
	})
	return nil
}

func TestHTTPRequestCancellationJoinsCloseCallbackTail(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	raw := &closeTailConn{Conn: left, entered: make(chan struct{}), allow: make(chan struct{})}
	requestRead := make(chan struct{})
	go func() { _, _ = stdhttp.ReadRequest(bufio.NewReader(right)); close(requestRead) }()
	client, owner := newRuntimeHTTPClient(t, func(context.Context, string, M.Socksaddr) (net.Conn, error) { return raw, nil })
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	var requestErr error
	go func() {
		_, requestErr = client.DialContext(ctx, "tcp", M.ParseSocksaddr("example.org:443"))
		close(returned)
	}()
	waitHTTPBarrier(t, requestRead)
	owner.Seal()
	cancel()
	waitHTTPBarrier(t, raw.entered)
	assertHTTPPending(t, returned)
	assertHTTPPending(t, owner.Closed())
	close(raw.allow)
	waitHTTPBarrier(t, returned)
	if !errors.Is(requestErr, context.Canceled) {
		t.Fatalf("request error: %v", requestErr)
	}
	waitHTTPBarrier(t, owner.Closed())
	if err := owner.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPPendingCreateCannotPublishAfterClose(t *testing.T) {
	entered, canceled, allow := make(chan struct{}), make(chan struct{}), make(chan struct{})
	left, right := net.Pipe()
	defer right.Close()
	client, err := NewClient(ClientOptions{Version: 1, Dialer: runtimeTestDialer(func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-allow // model a real dialer's post-cancellation tail
		return left, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	returned, closed := make(chan struct{}), make(chan struct{})
	var requestErr, closeErr error
	go func() {
		_, requestErr = client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443"))
		close(returned)
	}()
	waitHTTPBarrier(t, entered)
	go func() { closeErr = client.Close(); close(closed) }()
	waitHTTPBarrier(t, canceled)
	assertHTTPPending(t, returned)
	assertHTTPPending(t, closed)
	close(allow)
	waitHTTPBarrier(t, returned)
	waitHTTPBarrier(t, closed)
	if requestErr == nil {
		t.Fatal("late create published a connection")
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	client.access.Lock()
	remaining := len(client.connections)
	client.access.Unlock()
	if remaining != 0 {
		t.Fatal("late create remained in closed client")
	}
}

type httpRuntimeView struct {
	adapter.RuntimeView
	identity adapter.RuntimeRevision
}

func (v httpRuntimeView) Identity() adapter.RuntimeRevision { return v.identity }

func TestHTTPOldGenerationRetainsReceivingClientThroughReplacement(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	requestRead, respond := make(chan struct{}), make(chan struct{})
	go func() {
		_, _ = stdhttp.ReadRequest(bufio.NewReader(right))
		close(requestRead)
		<-respond
		_, _ = io.WriteString(right, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}()
	client, owner := newRuntimeHTTPClient(t, func(context.Context, string, M.Socksaddr) (net.Conn, error) { return left, nil })
	member, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	first, err := runtimegraph.NewGraph(httpRuntimeView{identity: adapter.RuntimeRevision{Incarnation: "http-test", Revision: 1}}, []adapter.RuntimeResourceLease{member})
	if err != nil {
		t.Fatal(err)
	}
	member.Release()
	store, err := runtimegraph.NewStore("http-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Publish(adapter.RuntimeRevision{Incarnation: "http-test"}, first); err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithRuntimeLease(context.Background(), lease)
	returned := make(chan struct{})
	var conn net.Conn
	var requestErr error
	go func() {
		conn, requestErr = client.DialContext(ctx, "tcp", M.ParseSocksaddr("example.org:443"))
		close(returned)
	}()
	waitHTTPBarrier(t, requestRead)
	second, err := runtimegraph.NewGraph(httpRuntimeView{identity: adapter.RuntimeRevision{Incarnation: "http-test", Revision: 2}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Publish(first.Identity(), second); err != nil {
		t.Fatal(err)
	}
	owner.Seal()
	lease.Release()
	assertHTTPPending(t, first.Drained())
	assertHTTPPending(t, owner.Closed())
	close(respond)
	waitHTTPBarrier(t, returned)
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	assertHTTPPending(t, owner.Closed())
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	waitHTTPBarrier(t, owner.Closed())
	waitHTTPBarrier(t, first.Drained())
	if err := owner.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.Seal()
	waitHTTPBarrier(t, store.Drained())
}

// Real I/O wrappers hold a lease until the socket call has returned, even when
// its Close has already returned and the caller canceled long before that.
type readTailConn struct {
	net.Conn
	entered chan struct{}
	allow   chan struct{}
}

func (c *readTailConn) Read(p []byte) (int, error) {
	close(c.entered)
	n, err := c.Conn.Read(p)
	<-c.allow
	return n, err
}

func TestHTTPReturnedConnectionJoinsReadTail(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	client, owner := newRuntimeHTTPClient(t, nil)
	raw := &readTailConn{Conn: left, entered: make(chan struct{}), allow: make(chan struct{})}
	conn, err := client.ownConnection(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	readDone, closeDone := make(chan struct{}), make(chan struct{})
	go func() { _, _ = conn.Read(make([]byte, 1)); close(readDone) }()
	waitHTTPBarrier(t, raw.entered)
	owner.Seal()
	go func() { _ = conn.Close(); close(closeDone) }()
	// Wait for the physical close via the peer, not an arbitrary sleep.
	_, _ = right.Read(make([]byte, 1))
	assertHTTPPending(t, closeDone)
	assertHTTPPending(t, owner.Closed())
	close(raw.allow)
	waitHTTPBarrier(t, readDone)
	waitHTTPBarrier(t, closeDone)
	waitHTTPBarrier(t, owner.Closed())
}

type incompleteHTTP3 struct{ closeErr error }

func (*incompleteHTTP3) DialContext(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (*incompleteHTTP3) OpenTunnel(context.Context, tunnelRequest) (DatagramStream, error) {
	return nil, os.ErrInvalid
}
func (*incompleteHTTP3) ResetConnection() {}
func (c *incompleteHTTP3) Close() error   { return c.closeErr }

func TestHTTPStandaloneTerminalDoesNotInventNativeJoin(t *testing.T) {
	client, err := NewClient(ClientOptions{Version: 1, DisableVersionFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	client.http3 = &incompleteHTTP3{}
	_, _ = client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443"))
	if err := client.Close(); err != nil {
		t.Fatalf("legacy Close changed: %v", err)
	}
	if err := client.RuntimeCloseAndWait(); !errors.Is(err, ErrRuntimeWorkerCompletionUnknown) {
		t.Fatalf("terminal owner accepted a hidden native tail: %v", err)
	}
}

func TestHTTPClosedCleanupDoesNotHideOtherFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		closeErr error
		unknown  bool
	}{
		{"repeated socket close", &net.OpError{Op: "close", Net: "tcp", Err: net.ErrClosed}, false},
		{"closed plus deadline", errors.Join(net.ErrClosed, context.DeadlineExceeded), true},
		{"closed plus failure", errors.Join(net.ErrClosed, errors.New("native close failed")), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(ClientOptions{Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			client.recordCloseError(test.closeErr)
			err = client.RuntimeCloseAndWait()
			if errors.Is(err, ErrRuntimeWorkerCompletionUnknown) != test.unknown {
				t.Fatalf("close classification: %v", err)
			}
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("cleanup uncertainty unwraps cancellation")
			}
		})
	}
}

func TestHTTPUnknownNativeCompletionRetainsDependencies(t *testing.T) {
	dependency, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "http-test", Sequence: 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dependencyLease, err := dependency.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	var scope *adapter.Scope
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "http-test", Sequence: 1}, []adapter.RuntimeResourceLease{dependencyLease}, func() error { return scope.Close() })
	if err != nil {
		t.Fatal(err)
	}
	dependencyLease.Release()
	scope = adapter.NewScope(owner.Context(), log.NewNOPFactory().Logger())
	client, err := NewClient(ClientOptions{Version: 1, RuntimeSource: owner, DisableVersionFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	client.http3 = &incompleteHTTP3{closeErr: context.DeadlineExceeded}
	scope.Add(client.Close)
	if _, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443")); err == nil {
		t.Fatal("expected native operation error")
	}
	dependency.Seal()
	owner.Seal()
	waitHTTPBarrier(t, owner.Closed())
	if err := owner.WaitClosed(context.Background()); !errors.Is(err, ErrRuntimeWorkerCompletionUnknown) {
		t.Fatalf("native uncertainty was filtered: %v", err)
	}
	assertHTTPPending(t, dependency.Closed())
	if err := client.Close(); !errors.Is(err, ErrRuntimeWorkerCompletionUnknown) {
		t.Fatalf("close result was not sticky: %v", err)
	}
}

// This fixture pauses the actual socket read beneath capsule parsing. The
// handshake consumes the first read; the runtime packet producer owns the next.
type packetReadTailConn struct {
	net.Conn
	reads   atomic.Int32
	entered chan struct{}
	allow   chan struct{}
}

func (c *packetReadTailConn) Read(p []byte) (int, error) {
	packetRead := c.reads.Add(1) == 2
	if packetRead {
		close(c.entered)
	}
	n, err := c.Conn.Read(p)
	if packetRead {
		<-c.allow
	}
	return n, err
}

func TestHTTPPacketDeadlineDoesNotCompleteReadWorker(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	raw := &packetReadTailConn{Conn: left, entered: make(chan struct{}), allow: make(chan struct{})}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		request, err := stdhttp.ReadRequest(bufio.NewReader(right))
		if err != nil {
			return
		}
		_, _ = io.WriteString(right, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+request.Header.Get("Upgrade")+"\r\nCapsule-Protocol: ?1\r\n\r\n")
	}()
	client, owner := newRuntimeHTTPClient(t, func(context.Context, string, M.Socksaddr) (net.Conn, error) { return raw, nil })
	packet, err := client.ListenPacket(context.Background(), M.ParseSocksaddr("192.0.2.53:53"))
	if err != nil {
		t.Fatal(err)
	}
	owned, ok := packet.(*runtimePacketConn)
	if !ok {
		t.Fatal("runtime used an unjoinable deadline producer")
	}
	waitHTTPBarrier(t, serverDone)
	waitHTTPBarrier(t, raw.entered)
	if err := packet.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := packet.ReadFrom(make([]byte, 512)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline result: %v", err)
	}
	owner.Seal()
	assertHTTPPending(t, owned.workerDone)
	assertHTTPPending(t, owner.Closed())
	closed := make(chan struct{})
	go func() { _ = packet.Close(); close(closed) }()
	_, _ = right.Read(make([]byte, 1)) // physical close occurred, worker tail remains
	assertHTTPPending(t, closed)
	assertHTTPPending(t, owned.workerDone)
	assertHTTPPending(t, owner.Closed())
	close(raw.allow)
	waitHTTPBarrier(t, owned.workerDone)
	waitHTTPBarrier(t, closed)
	waitHTTPBarrier(t, owner.Closed())
	if err := owner.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPNoTLSVersionFallbackUsesOwnedHTTP1(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			go func() {
				_, _ = stdhttp.ReadRequest(bufio.NewReader(right))
				_, _ = io.WriteString(right, "HTTP/1.1 200 Connection Established\r\n\r\nearly")
			}()
			client, err := NewClient(ClientOptions{Version: version, Dialer: runtimeTestDialer(func(context.Context, string, M.Socksaddr) (net.Conn, error) { return left, nil })})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443"))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := conn.(*clientOwnedConn); !ok {
				t.Fatal("HTTP1 fallback escaped client ownership")
			}
			payload := make([]byte, 5)
			if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "early" {
				t.Fatalf("prefetched handshake data: %q, %v", payload, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
