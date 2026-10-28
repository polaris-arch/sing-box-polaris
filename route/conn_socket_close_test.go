package route

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
)

type socketCloseState struct {
	calls   atomic.Int32
	result  error
	panicAt any
	entered chan struct{}
	release chan struct{}
}

func (s *socketCloseState) close() error {
	call := s.calls.Add(1)
	if s.entered != nil && call == 1 {
		close(s.entered)
	}
	if s.release != nil {
		<-s.release
	}
	if s.panicAt != nil {
		panic(s.panicAt)
	}
	if call != 1 {
		return net.ErrClosed
	}
	return s.result
}

type socketCloseConn struct {
	net.Conn
	state *socketCloseState
}

func (c *socketCloseConn) Close() error { return c.state.close() }

type socketClosePacketConn struct {
	net.PacketConn
	state *socketCloseState
}

func (c *socketClosePacketConn) Close() error { return c.state.close() }

type socketCloseOwner interface {
	io.Closer
	Attach(io.Closer) (io.Closer, bool)
	Detach()
}

type socketCloseCallback func() error

func (f socketCloseCallback) Close() error { return f() }

func trackSocketCloseFixture(m *ConnectionManager, packet bool, state *socketCloseState) socketCloseOwner {
	if packet {
		return m.TrackPacketConn(&socketClosePacketConn{state: state}).(socketCloseOwner)
	}
	return m.TrackConn(&socketCloseConn{state: state}).(socketCloseOwner)
}

func awaitSocketCloseResult(t *testing.T, results <-chan error) error {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("physical close observer did not join")
		return nil
	}
}

func TestTrackedSocketPhysicalCloseRetainsFirstResult(t *testing.T) {
	for _, packet := range []bool{false, true} {
		for _, result := range []error{nil, errors.New("actual first close failure"), net.ErrClosed} {
			name := "success"
			if result != nil {
				name = result.Error()
			}
			t.Run(map[bool]string{false: "TCP", true: "packet"}[packet]+"/"+name, func(t *testing.T) {
				m := NewConnectionManager(log.NewNOPFactory().Logger())
				state := &socketCloseState{result: result}
				tracked := trackSocketCloseFixture(m, packet, state)
				if m.Count() != 1 {
					t.Fatal("socket not tracked")
				}
				for range 3 {
					if got := tracked.Close(); got != result {
						t.Fatalf("first physical result changed: got=%v want=%v", got, result)
					}
				}
				if state.calls.Load() != 1 || m.Count() != 0 {
					t.Fatal("physical socket closed repeatedly or tracking retained")
				}
				if original, ok := tracked.Attach(new(managerTestCloser)); ok || original != nil {
					t.Fatal("closed socket allowed a new owner")
				}
			})
		}
	}
}

func TestTrackedSocketConcurrentPhysicalCloseJoins(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "packet"}[packet], func(t *testing.T) {
			m := NewConnectionManager(log.NewNOPFactory().Logger())
			state := &socketCloseState{result: errors.New("physical close result"), entered: make(chan struct{}), release: make(chan struct{})}
			unblock := sync.OnceFunc(func() { close(state.release) })
			defer unblock()
			tracked := trackSocketCloseFixture(m, packet, state)
			const callers = 16
			results := make(chan error, callers)
			for range callers {
				go func() { results <- tracked.Close() }()
			}
			managerAwait(t, state.entered)
			select {
			case <-results:
				t.Fatal("close returned while original physical close was still running")
			default:
			}
			unblock()
			for range callers {
				if got := awaitSocketCloseResult(t, results); got != state.result {
					t.Fatalf("concurrent observer lost first result: %v", got)
				}
			}
			if state.calls.Load() != 1 || m.Count() != 0 {
				t.Fatal("concurrent physical close did not converge")
			}
		})
	}
}

func TestTrackedSocketPhysicalPanicRemainsUnconfirmed(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "packet"}[packet], func(t *testing.T) {
			m := NewConnectionManager(log.NewNOPFactory().Logger())
			state := &socketCloseState{panicAt: errors.New("physical close panic")}
			tracked := trackSocketCloseFixture(m, packet, state)
			for range 2 {
				func() {
					defer func() {
						if got := recover(); got != state.panicAt {
							t.Fatalf("original panic not replayed: %v", got)
						}
					}()
					_ = tracked.Close()
					t.Error("physical panic became a successful completion")
				}()
			}
			if err := closeManagedSocket(tracked); err == nil || state.calls.Load() != 1 {
				t.Fatal("managed observer accepted a panicking physical close or retried it")
			}
		})
	}
}

func TestTrackedSocketCloseAllAndLateTrackingSharePhysicalResult(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "packet"}[packet], func(t *testing.T) {
			m := NewConnectionManager(log.NewNOPFactory().Logger())
			state := new(socketCloseState)
			tracked := trackSocketCloseFixture(m, packet, state)
			group := interrupt.NewGroup()
			var selected io.Closer
			if packet {
				selected = group.NewPacketConn(tracked.(net.PacketConn), false)
			} else {
				selected = group.NewConn(tracked.(net.Conn), false)
			}
			m.CloseAll()
			// Exercise the actual selector wrapper's second close after CloseAll.
			if err := selected.Close(); err != nil || state.calls.Load() != 1 {
				t.Fatalf("second owner saw a manufactured already-closed error: %v", err)
			}
			failure := &socketCloseState{result: errors.New("first close really failed")}
			failedTracked := trackSocketCloseFixture(m, packet, failure)
			m.CloseAll()
			if got := failedTracked.Close(); got != failure.result || failure.calls.Load() != 1 {
				t.Fatal("CloseAll hid a real physical close failure from the next owner")
			}
			second := new(socketCloseState)
			secondTracked := trackSocketCloseFixture(m, packet, second)
			if m.Count() != 1 || second.calls.Load() != 0 {
				t.Fatal("reusable CloseAll sealed future tracking")
			}
			if err := m.closeRuntimeTasks(); err != nil {
				t.Fatal(err)
			}
			if err := secondTracked.Close(); err != nil || second.calls.Load() != 1 {
				t.Fatal("stable terminal shutdown did not share physical result")
			}
			late := new(socketCloseState)
			lateTracked := trackSocketCloseFixture(m, packet, late)
			if late.calls.Load() != 1 || m.Count() != 0 {
				t.Fatal("terminal manager retained a late socket")
			}
			if err := lateTracked.Close(); err != nil || late.calls.Load() != 1 {
				t.Fatal("late tracked socket lost terminal physical result")
			}
		})
	}
}

func TestTrackedSocketAttachDetachPreservesSpliceOwnership(t *testing.T) {
	for _, packet := range []bool{false, true} {
		for _, mode := range []string{"owner-then-detach", "rollback-before-close", "duplicate-original-close", "reentrant-detach"} {
			t.Run(map[bool]string{false: "TCP", true: "packet"}[packet]+"/"+mode, func(t *testing.T) {
				m := NewConnectionManager(log.NewNOPFactory().Logger())
				state := &socketCloseState{result: errors.New("physical close result")}
				tracked := trackSocketCloseFixture(m, packet, state)
				ownerCalls := 0
				owner := socketCloseCallback(func() error {
					ownerCalls++
					if mode == "reentrant-detach" {
						tracked.Detach()
					}
					return nil
				})
				original, attached := tracked.Attach(owner)
				if !attached || original == nil {
					t.Fatal("fresh socket did not allow splice ownership")
				}
				if rejected, ok := tracked.Attach(new(managerTestCloser)); ok || rejected != nil {
					t.Fatal("second owner replaced the active splice")
				}
				switch mode {
				case "rollback-before-close":
					tracked.Detach()
					if state.calls.Load() != 0 || ownerCalls != 0 {
						t.Fatal("failed splice setup closed a still-live original socket")
					}
					if originalAgain, ok := tracked.Attach(owner); !ok || originalAgain == nil {
						t.Fatal("rollback prevented a valid subsequent splice")
					}
					tracked.Detach()
				case "duplicate-original-close":
					// Unix TUN duplicates its FD, then closes Attach's original.
					if err := original.Close(); err != state.result || state.calls.Load() != 1 {
						t.Fatal("splice original did not share the physical gate")
					}
					tracked.Detach()
				default:
					if err := tracked.Close(); err != nil || ownerCalls != 1 {
						t.Fatal("attached close no longer delegates to the splice owner")
					}
					if mode == "owner-then-detach" && state.calls.Load() != 0 {
						t.Fatal("owner delegation prematurely closed its physical original")
					}
					tracked.Detach()
				}
				if err := tracked.Close(); err != state.result || state.calls.Load() != 1 {
					t.Fatal("detach/terminal close did not preserve exact physical result")
				}
				if err := original.Close(); err != state.result || state.calls.Load() != 1 {
					t.Fatal("returned splice closer bypassed the shared physical gate")
				}
			})
		}
	}
}

func TestTrackedSocketConcurrentOwnerDetachAndOriginalClose(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "packet"}[packet], func(t *testing.T) {
			m := NewConnectionManager(log.NewNOPFactory().Logger())
			state := &socketCloseState{result: errors.New("physical close result"), entered: make(chan struct{}), release: make(chan struct{})}
			unblockPhysical := sync.OnceFunc(func() { close(state.release) })
			defer unblockPhysical()
			tracked := trackSocketCloseFixture(m, packet, state)
			ownerEntered, ownerRelease := make(chan struct{}), make(chan struct{})
			unblockOwner := sync.OnceFunc(func() { close(ownerRelease) })
			defer unblockOwner()
			original, ok := tracked.Attach(socketCloseCallback(func() error { close(ownerEntered); <-ownerRelease; return nil }))
			if !ok {
				t.Fatal("owner attachment failed")
			}
			ownerDone := make(chan error, 1)
			go func() { ownerDone <- tracked.Close() }()
			managerAwait(t, ownerEntered)
			detached := make(chan struct{})
			go func() { tracked.Detach(); close(detached) }()
			managerAwait(t, state.entered)
			originalDone := make(chan error, 1)
			go func() { originalDone <- original.Close() }()
			select {
			case <-detached:
				t.Fatal("detach returned before the original close completed")
			case <-originalDone:
				t.Fatal("splice original failed to join concurrent physical close")
			default:
			}
			unblockPhysical()
			managerAwait(t, detached)
			if got := awaitSocketCloseResult(t, originalDone); got != state.result {
				t.Fatalf("splice observer lost first physical result: %v", got)
			}
			unblockOwner()
			if got := awaitSocketCloseResult(t, ownerDone); got != nil {
				t.Fatalf("owner delegation changed result: %v", got)
			}
			if got := tracked.Close(); got != state.result || state.calls.Load() != 1 {
				t.Fatal("owner/detach/original race closed raw socket repeatedly")
			}
		})
	}
}
