package vmess

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
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	vm "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
)

type runtimeProtocolConn struct {
	readEntered, readProceed, closeEntered, closeProceed chan struct{}
	closes                                               atomic.Int32
}

func (c *runtimeProtocolConn) Read([]byte) (int, error) {
	close(c.readEntered)
	<-c.readProceed
	return 0, net.ErrClosed
}
func (*runtimeProtocolConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *runtimeProtocolConn) Close() error {
	c.closes.Add(1)
	close(c.closeEntered)
	<-c.closeProceed
	return nil
}
func (*runtimeProtocolConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*runtimeProtocolConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*runtimeProtocolConn) SetDeadline(time.Time) error      { return nil }
func (*runtimeProtocolConn) SetReadDeadline(time.Time) error  { return nil }
func (*runtimeProtocolConn) SetWriteDeadline(time.Time) error { return nil }

type runtimeProtocolTransport struct {
	conn  net.Conn
	fence *outbound.RuntimeIOFence
	stops atomic.Int32
}

func (c *runtimeProtocolTransport) DialContext(context.Context) (net.Conn, error) { return c.conn, nil }

func (c *runtimeProtocolTransport) Close() error { return c.fence.RuntimeCloseAndWait() }

func (c *runtimeProtocolTransport) StopRuntimeOperations() { c.stops.Add(1); _ = c.fence.Close() }

func TestRuntimeProtocolConstructedCarriersPreserveCompletion(t *testing.T) {
	runtimeProtocolCarrierCompletion(t, false)
}

func TestRuntimeProtocolDirectCarriersPreserveCompletion(t *testing.T) {
	runtimeProtocolCarrierCompletion(t, true)
}

type runtimeDirectProtocolDialer struct{ conn net.Conn }

func (d *runtimeDirectProtocolDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (*runtimeDirectProtocolDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("VMess UDP must use the actual TCP carrier")
}

type runtimeForeignProtocolWaiter struct {
	*runtimeProtocolConn
	waits atomic.Int32
}

func (c *runtimeForeignProtocolWaiter) RuntimeCloseAndWait() error {
	c.waits.Add(1)
	return nil // not an authoritative completion for the blocked raw methods
}

func runtimeProtocolCarrierCompletion(t *testing.T, direct bool) {
	t.Helper()
	for _, mode := range []string{"tcp", "udp", "listen", "packetaddr", "xudp"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			raw := &runtimeProtocolConn{make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), atomic.Int32{}}
			var readRelease, closeRelease sync.Once
			releaseRead := func() { readRelease.Do(func() { close(raw.readProceed) }) }
			releaseClose := func() { closeRelease.Do(func() { close(raw.closeProceed) }) }
			t.Cleanup(func() { releaseRead(); releaseClose() })
			foreign := &runtimeForeignProtocolWaiter{runtimeProtocolConn: raw}
			var transport *runtimeProtocolTransport
			cleanup := func() error { return nil }
			if !direct {
				physical, fence := outbound.WrapRuntimeOwnedConn(raw)
				transport = &runtimeProtocolTransport{conn: physical, fence: fence}
				cleanup = transport.Close
			}
			owner, err := runtimegraph.NewResourceOwner(ctx, adapter.RuntimeResourceID{Incarnation: "protocol", Sequence: 1}, nil, cleanup)
			if err != nil {
				t.Fatal(err)
			}
			client, err := vm.NewClient("00000000-0000-0000-0000-000000000001", "zero", 0)
			if err != nil {
				t.Fatal(err)
			}
			h := &Outbound{client: client, dialer: &runtimeDirectProtocolDialer{conn: foreign}, logger: log.NewNOPFactory().Logger(), runtimeSource: owner, packetAddr: mode == "packetaddr", xudp: mode == "xudp"}
			if transport != nil {
				h.transport = transport
			}
			destination := M.ParseSocksaddr("127.0.0.1:53")
			var closeConn func() error
			var readConn func()
			if mode == "listen" || mode == "packetaddr" || mode == "xudp" {
				conn, err := h.ListenPacket(ctx, destination)
				if err != nil {
					t.Fatal(err)
				}
				closeConn = conn.Close
				readConn = func() { _, _, _ = conn.ReadFrom(make([]byte, 64)) }
			} else {
				network := "tcp"
				if mode == "udp" {
					network = "udp"
				}
				conn, err := h.DialContext(ctx, network, destination)
				if err != nil {
					t.Fatal(err)
				}
				closeConn = conn.Close
				readConn = func() { _, _ = conn.Read(make([]byte, 64)) }
			}
			readDone := make(chan struct{})
			go func() { defer close(readDone); readConn() }()
			select {
			case <-raw.readEntered:
			case <-ctx.Done():
				t.Fatal("production protocol did not enter physical read")
			}
			owner.Seal() // Ordinary retirement alone must retain the old stream.
			select {
			case <-raw.closeEntered:
				t.Fatal("retirement killed old stream")
			default:
			}
			closed := make(chan error, 1)
			go func() { closed <- closeConn() }()
			select {
			case <-raw.closeEntered:
			case <-ctx.Done():
				t.Fatal("physical close not requested")
			}
			if snapshot := owner.CleanupSnapshot(); snapshot.Available && snapshot.References == 0 {
				t.Fatal("protocol released while worker still running")
			}
			releaseClose()
			select {
			case err = <-closed:
				t.Fatalf("method tail not joined: %v", err)
			default:
			}
			releaseRead()
			<-readDone
			select {
			case err = <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("protocol wrapper lost completion barrier")
			}
			if err = owner.WaitClosed(ctx); err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			for range 8 {
				workers.Go(func() {
					if err := closeConn(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Error(err)
					}
				})
			}
			workers.Wait()
			if raw.closes.Load() != 1 {
				t.Fatal("multiple physical close workers")
			}
			if foreign.waits.Load() != 0 {
				t.Fatal("direct construction trusted a foreign public completion interface")
			}
		})
	}
}

type runtimeDirectFailedClose struct {
	net.Conn
	panicClose bool
	closes     atomic.Int32
}

func (c *runtimeDirectFailedClose) Close() error {
	c.closes.Add(1)
	if c.panicClose {
		panic("unconfirmed direct parent close")
	}
	return errors.New("unconfirmed direct parent close")
}

func TestRuntimeDirectParentCloseFailureRetainsOwner(t *testing.T) {
	for _, failure := range []struct {
		name   string
		panics bool
	}{{"error", false}, {"panic", true}} {
		t.Run(failure.name, func(t *testing.T) {
			a, b := net.Pipe()
			t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
			raw := &runtimeDirectFailedClose{Conn: a, panicClose: failure.panics}
			owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "direct-failure", Sequence: 1}, nil, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			client, err := vm.NewClient("00000000-0000-0000-0000-000000000001", "zero", 0)
			if err != nil {
				t.Fatal(err)
			}
			h := &Outbound{client: client, dialer: &runtimeDirectProtocolDialer{conn: raw}, logger: log.NewNOPFactory().Logger(), runtimeSource: owner}
			conn, err := h.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
			if err != nil {
				t.Fatal(err)
			}
			owner.Seal()
			if err := conn.Close(); err == nil {
				t.Fatal("unconfirmed direct close released its owner")
			}
			if snapshot := owner.CleanupSnapshot(); !snapshot.Available || snapshot.References == 0 {
				t.Fatal("failed direct parent close lost its exact dependency reservation", snapshot)
			}
			if err := conn.Close(); err == nil || raw.closes.Load() != 1 {
				t.Fatal("failed close did not preserve its immutable single result", err, raw.closes.Load())
			}
		})
	}
}

func TestRuntimeProtocolFinalStopForwardsInterruption(t *testing.T) {
	raw := &runtimeProtocolConn{make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), atomic.Int32{}}
	physical, fence := outbound.WrapRuntimeOwnedConn(raw)
	transport := &runtimeProtocolTransport{conn: physical, fence: fence}
	h := &Outbound{transport: transport}
	h.StopRuntimeOperations()
	<-raw.closeEntered
	if transport.stops.Load() != 1 {
		t.Fatal("final interruption not forwarded")
	}
	close(raw.closeProceed)
	if err := fence.Wait(); err != nil {
		t.Fatal(err)
	}
}
