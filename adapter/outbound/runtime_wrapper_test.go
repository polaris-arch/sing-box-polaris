package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type lifecycleKnownWrapper struct {
	net.Conn
	err        error
	panicClose bool
}

func (c *lifecycleKnownWrapper) Close() error {
	if c.panicClose {
		panic("wrapper close")
	}
	return errors.Join(c.Conn.Close(), c.err)
}

func TestRuntimeKnownWrapperJoinsParentAndMethodBeforeRelease(t *testing.T) {
	for _, packet := range []bool{false, true} {
		raw := &lifecycleConn{readEntered: make(chan struct{}), readContinue: make(chan struct{}), closeEntered: make(chan struct{}), closeContinue: make(chan struct{})}
		parent, fence := WrapRuntimeOwnedConn(raw)
		wrapper := &lifecycleKnownWrapper{Conn: parent}
		var preserved net.Conn
		if packet {
			preserved = PreserveRuntimeConnClose(rawPacketWrapper{wrapper, parent.(net.PacketConn)}, parent)
		} else {
			preserved = PreserveRuntimeConnClose(wrapper, parent)
		}
		source := newLifecycleSource()
		ctx, release, err := adapterAcquire(source)
		if err != nil {
			t.Fatal(err)
		}
		outer := WrapRuntimeConn(ctx, release, preserved)
		readDone := make(chan struct{})
		go func() { defer close(readDone); _, _ = outer.Read(nil) }()
		<-raw.readEntered
		closed := make(chan error, 1)
		go func() { closed <- outer.Close() }()
		<-raw.closeEntered
		var pending sync.WaitGroup
		for range 8 {
			pending.Go(func() {
				if err := outer.Close(); err != ErrRuntimeClosePending {
					t.Errorf("concurrent close request: %v", err)
				}
			})
		}
		pending.Wait()
		if source.count() == 0 {
			t.Fatal("lease released before actual close")
		}
		close(raw.closeContinue)
		if source.count() == 0 {
			t.Fatal("lease released before admitted method returned")
		}
		close(raw.readContinue)
		<-readDone
		if err = <-closed; err != nil {
			t.Fatal(err)
		}
		if err = fence.Wait(); err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() {
				if err := outer.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		workers.Wait()
		if source.count() != 0 || raw.closes.Load() != 1 {
			t.Fatalf("refs=%d closes=%d", source.count(), raw.closes.Load())
		}
	}
}

// Both interfaces are intentionally preserved by the production packet helper.
type rawPacketWrapper struct {
	*lifecycleKnownWrapper
	net.PacketConn
}

func (c rawPacketWrapper) Close() error        { return c.lifecycleKnownWrapper.Close() }
func (c rawPacketWrapper) LocalAddr() net.Addr { return c.lifecycleKnownWrapper.LocalAddr() }
func (c rawPacketWrapper) SetDeadline(t time.Time) error {
	return c.lifecycleKnownWrapper.SetDeadline(t)
}

func (c rawPacketWrapper) SetReadDeadline(t time.Time) error {
	return c.lifecycleKnownWrapper.SetReadDeadline(t)
}

func (c rawPacketWrapper) SetWriteDeadline(t time.Time) error {
	return c.lifecycleKnownWrapper.SetWriteDeadline(t)
}

func TestRuntimeKnownWrapperFailureAndUnknownStayCharged(t *testing.T) {
	for _, mode := range []string{"parent-error", "parent-panic", "wrapper-error", "wrapper-panic", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			raw := &lifecycleConn{closeErr: nil, closePanic: mode == "parent-panic"}
			if mode == "parent-error" {
				raw.closeErr = io.ErrUnexpectedEOF
			}
			parent, _ := WrapRuntimeOwnedConn(raw)
			wrapper := &lifecycleKnownWrapper{Conn: parent, panicClose: mode == "wrapper-panic"}
			if mode == "wrapper-error" {
				wrapper.err = io.ErrUnexpectedEOF
			}
			preserved := PreserveRuntimeConnClose(wrapper, parent)
			if mode == "unknown" {
				preserved = wrapper
			} // No constructor capture means Pending remains unknown.
			source := newLifecycleSource()
			ctx, release, err := adapterAcquire(source)
			if err != nil {
				t.Fatal(err)
			}
			outer := WrapRuntimeConn(ctx, release, preserved)
			if err = outer.Close(); err == nil {
				t.Fatal("unknown completion certified")
			}
			if source.count() == 0 {
				t.Fatal("uncertain dependency released")
			}
			if err = outer.Close(); err == nil {
				t.Fatal("uncertainty was not sticky")
			}
		})
	}
}

func adapterAcquire(source *lifecycleSource) (context.Context, func(), error) {
	return adapter.AcquireRuntimeOperation(context.Background(), source)
}

func TestRuntimePacketKnownWrapperRetainsCompletion(t *testing.T) {
	raw := &lifecycleConn{closeEntered: make(chan struct{}), closeContinue: make(chan struct{})}
	parent, _ := WrapRuntimeOwnedConn(raw)
	wrapper := rawPacketWrapper{&lifecycleKnownWrapper{Conn: parent}, parent.(net.PacketConn)}
	preserved := PreserveRuntimePacketConnClose(wrapper, parent)
	source := newLifecycleSource()
	ctx, release, err := adapterAcquire(source)
	if err != nil {
		t.Fatal(err)
	}
	outer := WrapRuntimePacketConn(ctx, release, preserved)
	closed := make(chan error, 1)
	go func() { closed <- outer.Close() }()
	<-raw.closeEntered
	if source.count() == 0 {
		t.Fatal("packet wrapper released before physical completion")
	}
	close(raw.closeContinue)
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
	if source.count() != 0 || raw.closes.Load() != 1 {
		t.Fatal("packet completion did not release exactly once")
	}
}
