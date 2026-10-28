//go:build linux || android

package ping

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/pipe"
)

// These barriers run the production loopRead/fetchResponse bodies. No test
// substitutes a worker count, an already-closed completion channel or a timer
// for a worker's return. Timeouts below are watchdogs only.
func awaitPing(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not reach barrier")
	}
}

func awaitPingResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not return")
		return nil
	}
}

func assertPingPending(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("cleanup completed while real worker barrier is held: %v", err)
	default:
	}
}

type barrierSocket struct {
	readEntered chan struct{}
	closeCalled chan struct{}
	readRelease chan struct{}
	writeEntered chan struct{}
	writeRelease chan struct{}
	closeOnce sync.Once
	readOnce sync.Once
	writeOnce sync.Once
	closeErr error
	closePanic bool
	sendReply bool
	replySent bool // the single reader owns this field
}

func newBarrierSocket() *barrierSocket {
	return &barrierSocket{
		readEntered: make(chan struct{}),
		closeCalled: make(chan struct{}),
		readRelease: make(chan struct{}),
		writeEntered: make(chan struct{}),
	}
}

func (c *barrierSocket) Read([]byte) (int, error) { return 0, os.ErrInvalid }
func (c *barrierSocket) Write(b []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeEntered) })
	if c.writeRelease != nil {
		<-c.writeRelease
	}
	return len(b), nil
}
func (c *barrierSocket) Close() error {
	c.closeOnce.Do(func() { close(c.closeCalled) })
	if c.closePanic {
		panic("socket close uncertainty")
	}
	return c.closeErr
}
func (c *barrierSocket) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *barrierSocket) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (c *barrierSocket) SetDeadline(time.Time) error { return nil }
func (c *barrierSocket) SetReadDeadline(time.Time) error { return nil }
func (c *barrierSocket) SetWriteDeadline(time.Time) error { return nil }
func (c *barrierSocket) ReadMsgUDPAddrPort(b, _ []byte) (int, int, int, netip.AddrPort, error) {
	c.readOnce.Do(func() { close(c.readEntered) })
	if c.sendReply && !c.replySent {
		c.replySent = true
		packet := header.ICMPv4(b[:header.ICMPv4MinimumSize])
		packet.SetType(header.ICMPv4EchoReply)
		packet.SetCode(0)
		packet.SetIdent(1)
		packet.SetSequence(1)
		packet.SetChecksum(header.ICMPv4Checksum(packet, 0))
		return header.ICMPv4MinimumSize, 0, 0, netip.MustParseAddrPort("192.0.2.1:0"), nil
	}
	<-c.closeCalled
	<-c.readRelease
	return 0, 0, 0, netip.AddrPort{}, os.ErrClosed
}

func destinationWithSocket(ctx context.Context, socket *barrierSocket, writer PacketWriter) *Destination {
	address := netip.MustParseAddr("192.0.2.1")
	conn := &Conn{ctx: ctx, conn: socket, destination: address}
	conn.source.Store(netip.MustParseAddr("198.18.0.1"))
	conn.readMsg = func(b, oob []byte) (int, int, netip.Addr, error) {
		n, oobn, _, addr, err := socket.ReadMsgUDPAddrPort(b, oob)
		return n, oobn, addr.Addr(), err
	}
	d := &Destination{
		conn: conn, ctx: ctx, logger: logger.NOP(), destination: address,
		writer: writer, timeout: time.Hour, requests: make(map[pingRequest]int),
		requestHead: -1, requestTail: -1, requestFree: -1,
	}
	d.lastActive.Store(time.Now())
	d.startReader()
	return d
}

func fixturePort(socket *barrierSocket) *Port {
	p := NewPort(context.Background(), logger.NOP(), nil, time.Hour)
	p.connectDestination = func(ctx context.Context, _ logger.ContextLogger, _ control.Func, _ netip.Addr, writer PacketWriter, _ time.Duration) (*Destination, error) {
		return destinationWithSocket(ctx, socket, writer), nil
	}
	return p
}

func openFixtureFlow(t *testing.T, p *Port) *Destination {
	t.Helper()
	d, err := p.flowFor(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("192.0.2.1"), 1)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPortTerminalJoinsActualReadTailAndCanceledObserver(t *testing.T) {
	socket := newBarrierSocket()
	p := fixturePort(socket)
	d := openFixtureFlow(t, p)
	awaitPing(t, socket.readEntered)
	result := make(chan error, 1)
	go func() { result <- p.CloseAndWait() }()
	awaitPing(t, socket.closeCalled)
	assertPingPending(t, result)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("observer cancellation = %v", err)
	}
	p.flowAccess.Lock()
	owned := len(p.owned)
	p.flowAccess.Unlock()
	if owned != 1 {
		t.Fatalf("live dependency owner forgotten: %d", owned)
	}
	select {
	case <-d.readDone:
		t.Fatal("actual reader completion signaled before read returned")
	default:
	}
	close(socket.readRelease)
	if err := awaitPingResult(t, result); err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(ctx); err != nil {
		t.Fatalf("completed result lost to canceled observer: %v", err)
	}
	if _, err := p.flowFor(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("192.0.2.1"), 2); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("terminal port admitted new flow: %v", err)
	}
}

type barrierReturn struct {
	port *Port
	entered chan struct{}
	release chan struct{}
	returned chan struct{}
}

func (r *barrierReturn) ReturnHeadroom() int { return 0 }
func (r *barrierReturn) ReturnPackets([][]byte) [][]byte {
	close(r.entered)
	<-r.release
	// This is a real portWriter callback tail. A join holding flowAccess
	// would deadlock here after the test releases the callback barrier.
	r.port.flowAccess.Lock()
	r.port.flowAccess.Unlock()
	close(r.returned)
	return nil
}

func TestPortResetRetainsActualReturnCallbackUntilTerminalDrain(t *testing.T) {
	oldSocket := newBarrierSocket()
	oldSocket.sendReply = true
	close(oldSocket.readRelease)
	p := fixturePort(oldSocket)
	returnPath := &barrierReturn{port: p, entered: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
	if err := p.AttachReturn(returnPath); err != nil {
		t.Fatal(err)
	}
	old := openFixtureFlow(t, p)
	awaitPing(t, returnPath.entered)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	newSocket := newBarrierSocket()
	close(newSocket.readRelease)
	p.connectDestination = func(ctx context.Context, _ logger.ContextLogger, _ control.Func, _ netip.Addr, writer PacketWriter, _ time.Duration) (*Destination, error) {
		return destinationWithSocket(ctx, newSocket, writer), nil
	}
	current := openFixtureFlow(t, p)
	if current == old {
		t.Fatal("reset reused the closed destination")
	}
	result := make(chan error, 1)
	go func() { result <- p.CloseAndWait() }()
	awaitPing(t, newSocket.closeCalled)
	assertPingPending(t, result)
	p.flowAccess.Lock()
	retained := false
	for entry := range p.owned {
		if entry.destination == old {
			retained = true
		}
	}
	p.flowAccess.Unlock()
	if !retained {
		t.Fatal("reset dropped the live callback's ownership record")
	}
	close(returnPath.release)
	awaitPing(t, returnPath.returned)
	if err := awaitPingResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestPortShutdownWaitsPendingCreationAndRejectsItsPublication(t *testing.T) {
	socket := newBarrierSocket()
	close(socket.readRelease)
	p := fixturePort(socket)
	entered := make(chan struct{})
	release := make(chan struct{})
	p.connectDestination = func(ctx context.Context, _ logger.ContextLogger, _ control.Func, _ netip.Addr, writer PacketWriter, _ time.Duration) (*Destination, error) {
		close(entered)
		<-release
		return destinationWithSocket(ctx, socket, writer), nil
	}
	created := make(chan error, 1)
	go func() {
		_, err := p.flowFor(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("192.0.2.1"), 1)
		created <- err
	}()
	awaitPing(t, entered)
	result := make(chan error, 1)
	go func() { result <- p.CloseAndWait() }()
	awaitPing(t, p.ctx.Done())
	assertPingPending(t, result)
	close(release)
	if err := awaitPingResult(t, created); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("pending creation published after terminal seal: %v", err)
	}
	if err := awaitPingResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestPortCloseFailureAndPanicStayQuarantinedAfterActualExit(t *testing.T) {
	for _, test := range []struct {
		name string
		err error
		panicClose bool
	}{
		{name: "canceled", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "panic", panicClose: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			socket := newBarrierSocket()
			socket.closeErr = test.err
			socket.closePanic = test.panicClose
			p := fixturePort(socket)
			openFixtureFlow(t, p)
			awaitPing(t, socket.readEntered)
			result := make(chan error, 1)
			go func() { result <- p.CloseAndWait() }()
			awaitPing(t, socket.closeCalled)
			assertPingPending(t, result)
			close(socket.readRelease)
			err := awaitPingResult(t, result)
			if err == nil || E.IsCanceled(err) || E.IsClosed(err) {
				t.Fatalf("cleanup uncertainty could be filtered by Scope: %v", err)
			}
			p.flowAccess.Lock()
			retained := len(p.owned)
			p.flowAccess.Unlock()
			if retained != 1 {
				t.Fatalf("uncertain cleanup was not quarantined: %d", retained)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if repeated := p.Wait(ctx); repeated == nil || E.IsCanceled(repeated) {
				t.Fatalf("completed sticky uncertainty lost: %v", repeated)
			}
		})
	}
}

func fixtureUnprivileged(socket *barrierSocket) *UnprivilegedConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &UnprivilegedConn{
		ctx: ctx, cancel: cancel, destination: netip.MustParseAddr("192.0.2.1"),
		receiveChan: make(chan *unprivilegedResponse), readDeadline: pipe.MakeDeadline(),
		mapping: make(map[uint16]*unprivilegedSocket), owned: make(map[*unprivilegedSocket]struct{}),
		closeDone: make(chan struct{}),
		connectSocket: func(bool, control.Func, netip.Addr) (net.Conn, error) { return socket, nil },
	}
}

func echoBytes() []byte {
	packet := make(header.ICMPv4, header.ICMPv4MinimumSize)
	packet.SetType(header.ICMPv4Echo)
	packet.SetIdent(1)
	return packet
}

func TestUnprivilegedWaitJoinsRealFetchAndAdmittedWriteTails(t *testing.T) {
	socket := newBarrierSocket()
	socket.writeRelease = make(chan struct{})
	c := fixtureUnprivileged(socket)
	writeResult := make(chan error, 1)
	go func() { _, err := c.Write(echoBytes()); writeResult <- err }()
	awaitPing(t, socket.writeEntered)
	awaitPing(t, socket.readEntered)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- c.Wait(context.Background()) }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("observer = %v", err)
	}
	assertPingPending(t, result)
	close(socket.readRelease)
	// fetchResponse may now return, but the admitted real Write still runs.
	assertPingPending(t, result)
	close(socket.writeRelease)
	if err := awaitPingResult(t, writeResult); err != nil {
		t.Fatal(err)
	}
	if err := awaitPingResult(t, result); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(ctx); err != nil {
		t.Fatalf("completed fetch lost to cancellation: %v", err)
	}
}

func TestUnprivilegedShutdownWaitsPendingSocketCreation(t *testing.T) {
	socket := newBarrierSocket()
	close(socket.readRelease)
	c := fixtureUnprivileged(socket)
	entered := make(chan struct{})
	release := make(chan struct{})
	c.connectSocket = func(bool, control.Func, netip.Addr) (net.Conn, error) {
		close(entered)
		<-release
		return socket, nil
	}
	writeResult := make(chan error, 1)
	go func() { _, err := c.Write(echoBytes()); writeResult <- err }()
	awaitPing(t, entered)
	result := make(chan error, 1)
	go func() {
		err := c.Close()
		result <- E.Errors(err, c.Wait(context.Background()))
	}()
	awaitPing(t, c.ctx.Done())
	assertPingPending(t, result)
	close(release)
	if err := awaitPingResult(t, writeResult); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("post-seal socket write = %v", err)
	}
	if err := awaitPingResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestPortConstructorPanicRetainsUncertainty(t *testing.T) {
	p := NewPort(context.Background(), logger.NOP(), nil, time.Hour)
	p.controlFunc = func(netip.Addr) control.Func { panic("control callback panic") }
	_, err := p.flowFor(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("192.0.2.1"), 1)
	if err == nil {
		t.Fatal("constructor panic disappeared")
	}
	if err := p.CloseAndWait(); err == nil || E.IsCanceled(err) {
		t.Fatalf("constructor uncertainty disappeared during cleanup: %v", err)
	}
	p.flowAccess.Lock()
	retained := len(p.owned)
	p.flowAccess.Unlock()
	if retained != 1 {
		t.Fatal("uncertain constructor was forgotten")
	}
}

func TestPortTerminalJoinsFetchTailAfterDestinationReaderExited(t *testing.T) {
	socket := newBarrierSocket()
	unprivileged := fixtureUnprivileged(socket)
	p := NewPort(context.Background(), logger.NOP(), nil, time.Hour)
	var destination *Destination
	p.connectDestination = func(ctx context.Context, _ logger.ContextLogger, _ control.Func, address netip.Addr, writer PacketWriter, _ time.Duration) (*Destination, error) {
		conn := &Conn{ctx: ctx, conn: unprivileged, destination: address, readMsg: unprivileged.ReadMsg}
		destination = &Destination{
			conn: conn, ctx: ctx, logger: logger.NOP(), destination: address,
			writer: writer, timeout: time.Hour, requests: make(map[pingRequest]int),
			requestHead: -1, requestTail: -1, requestFree: -1,
		}
		destination.lastActive.Store(time.Now())
		destination.startReader()
		return destination, nil
	}
	openFixtureFlow(t, p)
	if _, err := unprivileged.Write(echoBytes()); err != nil {
		t.Fatal(err)
	}
	awaitPing(t, socket.readEntered)
	result := make(chan error, 1)
	go func() { result <- p.CloseAndWait() }()
	awaitPing(t, socket.closeCalled)
	awaitPing(t, destination.readDone)
	// The high-level read worker has exited, but the real fetchResponse
	// remains in its socket read tail. Parent completion must still wait.
	assertPingPending(t, result)
	close(socket.readRelease)
	if err := awaitPingResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestUnprivilegedPartialCreationFailureRetainsHandleOnCleanupUncertainty(t *testing.T) {
	socket := newBarrierSocket()
	socket.closeErr = context.DeadlineExceeded
	c := fixtureUnprivileged(socket)
	c.connectSocket = func(bool, control.Func, netip.Addr) (net.Conn, error) {
		return socket, errors.New("partially acquired socket")
	}
	if _, err := c.Write(echoBytes()); err == nil {
		t.Fatal("partial socket failure disappeared")
	}
	_ = c.Close()
	if err := c.Wait(context.Background()); err == nil || E.IsCanceled(err) {
		t.Fatalf("partial cleanup uncertainty disappeared: %v", err)
	}
	c.mappingAccess.Lock()
	retained := false
	for entry := range c.owned {
		if entry.conn == socket {
			retained = true
		}
	}
	c.mappingAccess.Unlock()
	if !retained {
		t.Fatal("partially acquired socket handle was forgotten")
	}
}

func TestUnprivilegedCreationPanicRetainsUncertainty(t *testing.T) {
	c := fixtureUnprivileged(newBarrierSocket())
	c.connectSocket = func(bool, control.Func, netip.Addr) (net.Conn, error) {
		panic("socket factory panic")
	}
	if _, err := c.Write(echoBytes()); err == nil {
		t.Fatal("socket creation panic disappeared")
	}
	_ = c.Close()
	if err := c.Wait(context.Background()); err == nil || E.IsCanceled(err) {
		t.Fatalf("socket creation uncertainty disappeared: %v", err)
	}
}
