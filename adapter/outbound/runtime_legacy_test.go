package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeLegacyKnownCloseJoinsAndPreservesCapabilities(t *testing.T) {
	for _, mode := range []string{"conn-packet", "packet", "cached-tls"} {
		t.Run(mode, func(t *testing.T) {
			raw := &lifecycleConn{readEntered: make(chan struct{}), readContinue: make(chan struct{}), closeEntered: make(chan struct{}), closeContinue: make(chan struct{})}
			var readOnce, closeOnce sync.Once
			releaseRead := func() { readOnce.Do(func() { close(raw.readContinue) }) }
			releaseClose := func() { closeOnce.Do(func() { close(raw.closeContinue) }) }
			t.Cleanup(func() { releaseRead(); releaseClose() })
			wait := func(done <-chan struct{}) {
				t.Helper()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("legacy carrier did not make progress")
				}
			}
			var closeConn func() error
			var read func()
			if mode == "packet" {
				parent, _ := WrapRuntimeOwnedPacketConn(raw)
				conn, err := ListenRuntimePacket(context.Background(), nil, func(context.Context) (net.PacketConn, error) { return parent, nil })
				if err != nil {
					t.Fatal(err)
				}
				closeConn = conn.Close
				read = func() { _, _, _ = conn.ReadFrom(nil) }
			} else {
				parent, _ := WrapRuntimeOwnedConn(raw)
				if mode == "cached-tls" {
					parent = PreserveRuntimeTLSState(parent, tls.ConnectionState{HandshakeComplete: true})
				}
				conn, err := DialRuntimeConn(context.Background(), nil, func(context.Context) (net.Conn, error) { return parent, nil })
				if err != nil {
					t.Fatal(err)
				}
				closeConn = conn.Close
				read = func() { _, _ = conn.Read(nil) }
				if mode == "conn-packet" {
					packet, ok := conn.(net.PacketConn)
					if !ok {
						t.Fatal("legacy view lost dual packet capability")
					}
					if n, err := packet.WriteTo([]byte("packet"), &net.UDPAddr{}); n != 6 || err != nil {
						t.Fatal(n, err)
					}
				} else {
					observed, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
					if !ok || !observed.ConnectionState().HandshakeComplete {
						t.Fatal("legacy view lost cached TLS observation")
					}
				}
			}
			readDone := make(chan struct{})
			go func() { defer close(readDone); read() }()
			wait(raw.readEntered)
			closed := make(chan error, 1)
			go func() { closed <- closeConn() }()
			wait(raw.closeEntered)
			releaseClose()
			select {
			case err := <-closed:
				t.Fatal("legacy Close did not join the method tail", err)
			default:
			}
			releaseRead()
			wait(readDone)
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("legacy Close did not finish")
			}
			if err := closeConn(); err != nil || raw.closes.Load() != 1 {
				t.Fatal("legacy Close lost its unique result", err)
			}
		})
	}
}

type runtimeLegacyForeignWaiter struct {
	*lifecycleConn
	waits atomic.Int32
}

func (c *runtimeLegacyForeignWaiter) RuntimeCloseAndWait() error { c.waits.Add(1); return nil }

func TestRuntimeLegacyDoesNotTrustForeignCompletion(t *testing.T) {
	failure := errors.New("foreign close failed")
	raw := &runtimeLegacyForeignWaiter{lifecycleConn: &lifecycleConn{closeErr: failure}}
	conn, err := DialRuntimeConn(context.Background(), nil, func(context.Context) (net.Conn, error) { return raw, nil })
	if err != nil || conn != raw {
		t.Fatal("foreign carrier was reinterpreted", err)
	}
	if err := conn.Close(); err != failure || raw.waits.Load() != 0 || raw.closes.Load() != 1 {
		t.Fatal("foreign completion was trusted", err)
	}
}

func TestRuntimeLegacyKnownCloseKeepsErrorAndPanicUncertain(t *testing.T) {
	for _, panics := range []bool{false, true} {
		raw := &lifecycleConn{closeErr: errors.New("unknown physical close"), closePanic: panics}
		parent, _ := WrapRuntimeOwnedConn(raw)
		conn, err := DialRuntimeConn(context.Background(), nil, func(context.Context) (net.Conn, error) { return parent, nil })
		if err != nil {
			t.Fatal(err)
		}
		first := conn.Close()
		if first == nil || conn.Close() != first || raw.closes.Load() != 1 {
			t.Fatal("legacy close laundered uncertainty", first)
		}
	}
}
