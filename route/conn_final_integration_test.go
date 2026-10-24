package route

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	out "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

type finalVirtualDialer struct {
	source adapter.RuntimeResourceSource
	conn   net.Conn
}

func (d finalVirtualDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return out.DialRuntimeConn(ctx, d.source, func(context.Context) (net.Conn, error) { return d.conn, nil })
}
func (d finalVirtualDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("not called")
}

type finalReadObserved struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *finalReadObserved) Read(b []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Read(b)
}

// This tests a shared route/lease contract with actual bidirectional Copy loops,
// not MASQUE/Cronet, a full Box, or the CI failure's unretained error body.
func TestFinalLogicalFlowActualTCPAndOwner(t *testing.T) {
	t.Log("entered actual shared route NewConnection/Copy/owner before-reproduction")
	host, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw, echo := net.Pipe()
	defer raw.Close()
	defer echo.Close()
	incoming, caller := net.Pipe()
	defer incoming.Close()
	defer caller.Close()
	cleanupStarted := make(chan struct{})
	owner, err := runtimegraph.NewResourceOwner(host, adapter.RuntimeResourceID{Incarnation: "review-virtual-flow", Sequence: 1}, nil, func() error { close(cleanupStarted); return raw.Close() })
	if err != nil {
		t.Fatal(err)
	}
	parent, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Release()
	defer owner.Seal()
	inboundObserved := &finalReadObserved{Conn: incoming, entered: make(chan struct{})}
	outboundObserved := &finalReadObserved{Conn: raw, entered: make(chan struct{})}
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	flowDone := make(chan struct{})
	var doneOnce sync.Once
	manager.NewConnection(adapter.ContextWithRuntimeResourceLease(host, parent), finalVirtualDialer{owner, outboundObserved}, inboundObserved, adapter.InboundContext{Destination: M.ParseSocksaddr("virtual.invalid:443")}, func(error) { doneOnce.Do(func() { close(flowDone) }) })
	for _, ready := range []<-chan struct{}{inboundObserved.entered, outboundObserved.entered} {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("copy worker did not start")
		}
	}
	exchange := func(writer net.Conn, reader net.Conn, payload string) {
		t.Helper()
		writer.SetWriteDeadline(time.Now().Add(time.Second))
		reader.SetReadDeadline(time.Now().Add(time.Second))
		defer writer.SetWriteDeadline(time.Time{})
		defer reader.SetReadDeadline(time.Time{})
		errc := make(chan error, 1)
		go func() { _, err := io.WriteString(writer, payload); errc <- err }()
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(reader, received); err != nil {
			t.Fatal(err)
		}
		if string(received) != payload {
			t.Fatal("payload changed")
		}
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
	exchange(caller, echo, "real-upload")
	exchange(echo, caller, "real-download")
	if n := manager.Count(); n != 0 {
		t.Fatalf("unexpected tracked physical sockets: %d", n)
	}
	if n := manager.diagnosticTasks.Load(); n != 2 {
		t.Fatalf("expected 2 actual copy tasks, got %d", n)
	}
	// Reproduce final host cancellation + sealed owner + actual manager CloseAll.
	parent.Release()
	owner.Seal()
	manager.CloseAll()
	exchange(caller, echo, "retired-hot-upload")
	exchange(echo, caller, "retired-hot-download")
	cancel()
	observer, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	if err := owner.WaitClosed(observer); err != context.DeadlineExceeded {
		t.Fatalf("expected observed live owner, got %v", err)
	}
	select {
	case <-cleanupStarted:
		t.Fatal("owner cleanup started despite live virtual flow")
	default:
	}
	if n := manager.diagnosticTasks.Load(); n != 2 {
		t.Fatalf("copy tasks exited before actual close: %d", n)
	}
	select {
	case <-flowDone:
		t.Fatal("CloseAll unexpectedly closed untracked flow")
	default:
	}
	// Final-only logical close, not caller EOF, must retire both actual Copy tails.
	manager.StopFinal()
	closed := make(chan error, 1)
	go func() { closed <- manager.closeRuntimeTasks() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("manager did not join after real flow close")
	}
	ctx, stop2 := context.WithTimeout(context.Background(), time.Second)
	defer stop2()
	if err := owner.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-flowDone:
	default:
		t.Fatal("terminal callback missing")
	}
	t.Log("actual bidirectional payload passed; host cancel+owner seal+CloseAll left virtual flow alive; new final-only logical stop joined tasks and released owner")
}

// Both packet-copy workers really block in distinct virtual stream-backed
// packet objects. No raw physical registry entry can rescue this final close.
type finalPacketDialer struct {
	source adapter.RuntimeResourceSource
	conn   net.PacketConn
}

func (d finalPacketDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	panic("not used")
}
func (d finalPacketDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return out.ListenRuntimePacket(ctx, d.source, func(context.Context) (net.PacketConn, error) { return d.conn, nil })
}
func TestFinalLogicalFlowActualPacketCopyAndOwner(t *testing.T) {
	host, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw, peer := net.Pipe()
	defer peer.Close()
	defer raw.Close()
	incoming, client := net.Pipe()
	defer client.Close()
	defer incoming.Close()
	owner, err := runtimegraph.NewResourceOwner(host, adapter.RuntimeResourceID{Incarnation: "final-packet-flow", Sequence: 1}, nil, func() error { return raw.Close() })
	if err != nil {
		t.Fatal(err)
	}
	parent, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Release()
	defer owner.Seal()
	a := &finalReadObserved{Conn: incoming, entered: make(chan struct{})}
	b := &finalReadObserved{Conn: raw, entered: make(chan struct{})}
	local := bufio.NewPacketConn(bufio.NewUnbindPacketConn(a))
	remote := bufio.NewUnbindPacketConn(b)
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	manager.NewPacketConnection(adapter.ContextWithRuntimeResourceLease(host, parent), finalPacketDialer{owner, remote}, local, adapter.InboundContext{Destination: M.ParseSocksaddr("virtual.invalid:12345")}, nil)
	managerAwait(t, a.entered)
	managerAwait(t, b.entered)
	if manager.Count() != 0 || manager.diagnosticTasks.Load() != 2 {
		t.Fatal("expected actual two virtual packet workers and no physical sockets")
	}
	cancel()
	parent.Release()
	owner.Seal()
	manager.CloseAll()
	ctx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	err = owner.WaitClosed(ctx)
	stop()
	if err != context.DeadlineExceeded {
		t.Fatalf("legacy CloseAll did not reproduce retained packet flow: %v", err)
	}
	manager.StopFinal()
	if err = finalAwaitClose(t, manager); err != nil {
		t.Fatal(err)
	}
	ctx, stop = context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = owner.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
	if manager.diagnosticTasks.Load() != 0 {
		t.Fatal("packet tails remain")
	}
}

type finalHalfSource struct {
	net.Conn
	eof <-chan struct{}
}

func (c *finalHalfSource) Read([]byte) (int, error) { <-c.eof; return 0, io.EOF }

type finalHalfRemote struct {
	net.Conn
	closedWrite chan struct{}
	once        sync.Once
}

func (c *finalHalfRemote) CloseWrite() error { c.once.Do(func() { close(c.closedWrite) }); return nil }
func TestFinalLogicalFlowActualHalfCloseKeepsDownload(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	incoming, client := net.Pipe()
	defer incoming.Close()
	defer client.Close()
	eof := make(chan struct{})
	remote := &finalHalfRemote{Conn: raw, closedWrite: make(chan struct{})}
	source := &finalHalfSource{Conn: incoming, eof: eof}
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	manager.NewConnection(context.Background(), finalVirtualDialer{conn: remote}, source, adapter.InboundContext{Destination: M.ParseSocksaddr("half.invalid:443")}, nil)
	close(eof)
	managerAwait(t, remote.closedWrite)
	wrote := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("reply-after-upload-EOF")); wrote <- err }()
	client.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, len("reply-after-upload-EOF"))
	if _, err := io.ReadFull(client, b); err != nil {
		t.Fatal(err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if string(b) != "reply-after-upload-EOF" {
		t.Fatal("half-close reply changed")
	}
	manager.access.Lock()
	n := len(manager.flows)
	manager.access.Unlock()
	if n != 1 {
		t.Fatal("first direction removed live download flow")
	}
	manager.StopFinal()
	if err := finalAwaitClose(t, manager); err != nil {
		t.Fatal(err)
	}
}

func finalTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return server, client
}

func TestFinalLogicalFlowRealTCPCloseRace(t *testing.T) {
	for i := 0; i < 20; i++ {
		socket, peer := finalTCPPair(t)
		m := finalManager()
		_, _, setup := finalFlow(t, m, socket)
		done := make(chan struct{})
		go func() { _ = socket.Close(); close(done) }()
		m.StopFinal()
		setup()
		managerAwait(t, done)
		if err := finalAwaitClose(t, m); err != nil {
			t.Fatal(err)
		}
		peer.Close()
	}
}

func TestFinalLogicalFlowRealTCPHalfClose(t *testing.T) {
	incoming, client := finalTCPPair(t)
	remote, server := finalTCPPair(t)
	m := finalManager()
	m.NewConnection(context.Background(), finalVirtualDialer{conn: remote}, incoming, adapter.InboundContext{Destination: M.ParseSocksaddr("half.invalid:443")}, nil)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := server.Read(one[:]); err != io.EOF {
		t.Fatalf("expected actual TCP shutdown EOF: %v", err)
	}
	if _, err := server.Write([]byte("TCP-half-open-reply")); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, len("TCP-half-open-reply"))
	if _, err := io.ReadFull(client, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "TCP-half-open-reply" {
		t.Fatal("real half-close reply changed")
	}
	m.access.Lock()
	live := len(m.flows)
	m.access.Unlock()
	if live != 1 {
		t.Fatal("real TCP first EOF discarded flow")
	}
	m.StopFinal()
	if err := finalAwaitClose(t, m); err != nil {
		t.Fatal(err)
	}
}

func TestFinalLogicalFlowListenerSocksRuntimeCompletion(t *testing.T) {
	for i := 0; i < 20; i++ {
		socket, _ := finalTCPPair(t)
		var releases atomic.Int32
		carrier := out.WrapRuntimeConn(context.Background(), func() { releases.Add(1) }, socket)
		ctx := out.ContextWithRuntimeInboundClose(context.Background(), carrier)
		lazy := socks.NewLazyConn(carrier, 5)
		var callbacks atomic.Int32
		var once sync.Once
		top := &runtimeConn{Conn: lazy, finish: func(error) { once.Do(func() { callbacks.Add(1) }) }}
		m := finalManager()
		_, _, setup, err := m.reserveFlow(ctx, top)
		if err != nil {
			t.Fatal(err)
		}
		raced := make(chan struct{})
		go func() { _ = top.Close(); close(raced) }()
		m.StopFinal()
		setup()
		managerAwait(t, raced)
		if err = finalAwaitClose(t, m); err != nil {
			t.Fatal(err)
		}
		if callbacks.Load() != 1 || releases.Load() != 1 {
			t.Fatal("actual listener/SOCKS/runtime closure tail lost")
		}
	}
}
