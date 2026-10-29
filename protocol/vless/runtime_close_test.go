package vless

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
	vl "github.com/sagernet/sing-vmess/vless"
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
	for _, mode := range []string{"tcp", "udp", "listen", "packetaddr", "xudp"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			raw := &runtimeProtocolConn{make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), atomic.Int32{}}
			physical, fence := outbound.WrapRuntimeOwnedConn(raw)
			transport := &runtimeProtocolTransport{conn: physical, fence: fence}
			owner, err := runtimegraph.NewResourceOwner(ctx, adapter.RuntimeResourceID{Incarnation: "protocol", Sequence: 1}, nil, transport.Close)
			if err != nil {
				t.Fatal(err)
			}
			client, err := vl.NewClient("00000000-0000-0000-0000-000000000001", "", log.NewNOPFactory().Logger())
			if err != nil {
				t.Fatal(err)
			}
			h := &Outbound{client: client, transport: transport, logger: log.NewNOPFactory().Logger(), runtimeSource: owner, packetAddr: mode == "packetaddr", xudp: mode == "xudp"}
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
			close(raw.closeProceed)
			select {
			case err = <-closed:
				t.Fatalf("method tail not joined: %v", err)
			default:
			}
			close(raw.readProceed)
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
