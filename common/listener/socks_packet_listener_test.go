package listener

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type socksPacketFixture struct {
	closes   atomic.Int32
	closeErr error
}

func (*socksPacketFixture) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, net.ErrClosed }
func (*socksPacketFixture) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *socksPacketFixture) Close() error                            { c.closes.Add(1); return c.closeErr }

func (*socksPacketFixture) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}
}
func (*socksPacketFixture) SetDeadline(time.Time) error      { return nil }
func (*socksPacketFixture) SetReadDeadline(time.Time) error  { return nil }
func (*socksPacketFixture) SetWriteDeadline(time.Time) error { return nil }

func TestSOCKSPacketAllocationCommitRollback(t *testing.T) {
	for _, mode := range []string{"TCP-no-allocation", "UDP-handoff", "response-write-error", "first-packet-error-already-closed", "handoff-error"} {
		t.Run(mode, func(t *testing.T) {
			raw := new(socksPacketFixture)
			allocations := 0
			transaction := NewSOCKSPacketListener(func(_ net.ListenConfig, _ context.Context, network, address string) (net.PacketConn, error) {
				allocations++
				if network != "udp4" || address != "127.0.0.1:0" {
					t.Fatal("listen scope changed")
				}
				return raw, nil
			})
			var conn net.PacketConn
			if mode != "TCP-no-allocation" {
				var err error
				conn, err = transaction.ListenPacket(net.ListenConfig{}, context.Background(), "udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				if _, rawAccess := conn.(interface{ Upstream() any }); rawAccess {
					t.Fatal("rollback wrapper exposes raw carrier")
				}
			}
			var failure error
			if mode != "TCP-no-allocation" && mode != "UDP-handoff" {
				failure = errors.New(mode)
			}
			if mode == "first-packet-error-already-closed" {
				_ = conn.Close()
			}
			err := transaction.Finish(failure)
			if !errors.Is(err, failure) {
				t.Fatal("original handshake error was lost")
			}
			if failure != nil && raw.closes.Load() != 1 {
				t.Fatal("rollback must close exactly once")
			}
			if mode == "UDP-handoff" {
				if raw.closes.Load() != 0 {
					t.Fatal("successful handoff closed the UDP carrier")
				}
				_ = transaction.Finish(errors.New("late duplicate finish"))
				if raw.closes.Load() != 0 {
					t.Fatal("late rollback closed transferred carrier")
				}
				_ = conn.Close()
				_ = conn.Close()
				if raw.closes.Load() != 1 {
					t.Fatal("terminal UDP close was not exact-once")
				}
			}
			if mode == "TCP-no-allocation" && (allocations != 0 || raw.closes.Load() != 0) {
				t.Fatal("TCP path allocated UDP")
			}
			if _, err := transaction.ListenPacket(net.ListenConfig{}, context.Background(), "udp4", "127.0.0.1:0"); err == nil {
				t.Fatal("finished handshake allocated new carrier")
			}
		})
	}
}

func TestSOCKSPacketAllocationFailureAndDuplicate(t *testing.T) {
	for _, mode := range []string{"bind-failure", "partial-bind-failure", "nil-carrier", "duplicate", "canceled-context"} {
		t.Run(mode, func(t *testing.T) {
			raw := new(socksPacketFixture)
			allocations := 0
			bindErr := errors.New("bind failed")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled-context" {
				cancel()
			}
			transaction := NewSOCKSPacketListener(func(_ net.ListenConfig, got context.Context, _, _ string) (net.PacketConn, error) {
				allocations++
				if got != ctx {
					t.Fatal("listen context changed")
				}
				switch mode {
				case "bind-failure":
					return nil, bindErr
				case "partial-bind-failure":
					return raw, bindErr
				case "nil-carrier":
					return nil, nil
				case "canceled-context":
					return nil, got.Err()
				default:
					return raw, nil
				}
			})
			_, err := transaction.ListenPacket(net.ListenConfig{}, ctx, "udp4", "127.0.0.1:0")
			if mode == "duplicate" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = transaction.ListenPacket(net.ListenConfig{}, ctx, "udp4", "127.0.0.1:0")
			}
			if err == nil || allocations != 1 {
				t.Fatal("invalid allocation was accepted or repeated")
			}
			if mode == "canceled-context" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost")
			}
			_ = transaction.Finish(err)
			want := int32(0)
			if mode == "duplicate" || mode == "partial-bind-failure" {
				want = 1
			}
			if raw.closes.Load() != want {
				t.Fatalf("closes=%d want=%d", raw.closes.Load(), want)
			}
		})
	}
}

func TestSOCKSPacketConcurrentControlCloseAndRollbackPreserveError(t *testing.T) {
	closeErr, handshakeErr := errors.New("physical close uncertain"), errors.New("first packet failed")
	raw := &socksPacketFixture{closeErr: closeErr}
	transaction := NewSOCKSPacketListener(func(net.ListenConfig, context.Context, string, string) (net.PacketConn, error) { return raw, nil })
	conn, err := transaction.ListenPacket(net.ListenConfig{}, context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if !errors.Is(conn.Close(), closeErr) {
				t.Error("close error changed")
			}
		})
	}
	err = transaction.Finish(handshakeErr)
	group.Wait()
	if !errors.Is(err, closeErr) || !errors.Is(err, handshakeErr) || raw.closes.Load() != 1 {
		t.Fatal("rollback hid a cleanup failure or repeated the physical close")
	}
}
