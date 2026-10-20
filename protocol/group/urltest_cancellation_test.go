package group

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
)

// Deliberately leave cancellation callbacks pending until their registrations
// are stopped, so publication cannot depend on the AfterFunc goroutine winning.
type pendingURLTestCancelContext struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func (c *pendingURLTestCancelContext) Done() <-chan struct{} {
	return c.done
}

func (c *pendingURLTestCancelContext) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}

func (c *pendingURLTestCancelContext) cancel() {
	c.once.Do(func() { close(c.done) })
}

func (*pendingURLTestCancelContext) AfterFunc(func()) func() bool {
	var once sync.Once
	return func() bool {
		stopped := false
		once.Do(func() { stopped = true })
		return stopped
	}
}

func awaitURLTestWorkers(t *testing.T, g *URLTestGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		g.workers.Wait()
		close(done)
	}()
	awaitEpochSignal(t, done)
}

func TestManualCancellationBeforeCallbackPreservesActiveHistoryAndSelection(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, failure := range []bool{false, true} {
			name := map[bool]string{false: "direct", true: "nested"}[nested] + "/" + map[bool]string{false: "success", true: "error"}[failure]
			t.Run(name, func(t *testing.T) {
				g, history, _ := epochTestGroup(t)
				probeOwner := g
				if nested {
					child, err := NewURLTestGroup(g.ctx, nil, log.NewNOPFactory().Logger(), []adapter.Outbound{&epochTestOutbound{tag: "node"}}, "", time.Hour, 1, 2*time.Hour, false)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						child.Close()
						awaitEpochSignal(t, child.Done())
					})
					probeOwner = child
					g.outbounds = []adapter.Outbound{&URLTest{
						Adapter: outbound.NewAdapter(C.TypeURLTest, "nested", []string{N.NetworkTCP, N.NetworkUDP}, []string{"node"}),
						group:   child,
						tags:    []string{"node"},
					}}
					child.access.Lock()
					child.started = true
					child.access.Unlock()
				}
				prior := &epochTestOutbound{tag: "prior"}
				g.selection.Store(&urlTestSelection{tcp: prior, udp: prior})
				probeOwner.selection.Store(&urlTestSelection{tcp: prior, udp: prior})
				if !history.StoreIfCurrent(history.Epoch(), "node", &adapter.URLTestHistory{Delay: 10}) {
					t.Fatal("initial active history unavailable")
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				t.Cleanup(func() {
					releaseOnce.Do(func() { close(release) })
					awaitURLTestWorkers(t, g)
					awaitURLTestWorkers(t, probeOwner)
				})
				probeOwner.probe = func(context.Context, string, N.Dialer) (uint16, error) {
					close(entered)
					<-release
					if failure {
						return 0, errors.New("late probe failure")
					}
					return 2, nil
				}
				g.access.Lock()
				g.started = true
				g.access.Unlock()
				caller := &pendingURLTestCancelContext{Context: context.Background(), done: make(chan struct{})}
				defer caller.cancel()
				waiter := make(chan error, 1)
				go func() {
					_, err := g.requestCheck(caller, true, true)
					waiter <- err
				}()
				awaitEpochSignal(t, entered)
				caller.cancel()
				select {
				case err := <-waiter:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("manual waiter cancellation: %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("manual waiter ignored cancellation")
				}
				releaseOnce.Do(func() { close(release) })
				awaitURLTestWorkers(t, g)
				awaitURLTestWorkers(t, probeOwner)
				// Check before Close: shutdown would clear history and hide a write.
				if got := history.LoadURLTestHistory("node"); got == nil || got.Delay != 10 {
					t.Fatal("canceled raw probe changed active history")
				}
				if g.selected().tcp != prior || g.selected().udp != prior || probeOwner.selected().tcp != prior || probeOwner.selected().udp != prior {
					t.Fatal("canceled manual pass changed selection")
				}
			})
		}
	}
}

func TestHostOwnedRefreshPublishesAfterAdmittingCallerCancellation(t *testing.T) {
	for _, coalesced := range []bool{false, true} {
		t.Run(map[bool]string{false: "prelatched", true: "coalesced"}[coalesced], func(t *testing.T) {
			g, history, _ := epochTestGroup(t)
			if !coalesced {
				_, _ = g.requestCheck(g.ctx, true, false)
			}
			g.access.Lock()
			g.started = true
			g.access.Unlock()
			entered, release := make(chan struct{}), make(chan struct{})
			nextEntered, nextRelease := make(chan struct{}), make(chan struct{})
			var firstOnce, nextOnce sync.Once
			t.Cleanup(func() {
				firstOnce.Do(func() { close(release) })
				nextOnce.Do(func() { close(nextRelease) })
				awaitURLTestWorkers(t, g)
			})
			var calls atomic.Int32
			g.probe = func(context.Context, string, N.Dialer) (uint16, error) {
				if calls.Add(1) == 1 {
					close(entered)
					<-release
					return 2, nil
				}
				close(nextEntered)
				<-nextRelease
				return 9, nil
			}
			originalCaller := &pendingURLTestCancelContext{Context: context.Background(), done: make(chan struct{})}
			defer originalCaller.cancel()
			caller := &pendingURLTestCancelContext{
				Context: context.WithValue(context.Background(), urlTestCallerGuardKey{}, func() bool { return urlTestCanPublish(originalCaller) }),
				done:    make(chan struct{}),
			}
			defer caller.cancel()
			if _, err := g.requestCheck(caller, true, false); err != nil {
				t.Fatal(err)
			}
			awaitEpochSignal(t, entered)
			if coalesced {
				_, _ = g.requestCheck(g.ctx, true, false)
			}
			caller.cancel()
			originalCaller.cancel()
			firstOnce.Do(func() { close(release) })
			want, wantCalls := uint16(2), int32(1)
			if coalesced {
				awaitEpochSignal(t, nextEntered)
				if history.LoadURLTestHistory("node") != nil || g.selection.Load() != nil {
					t.Fatal("canceled first pass published before host successor")
				}
				nextOnce.Do(func() { close(nextRelease) })
				want, wantCalls = 9, 2
			}
			awaitURLTestWorkers(t, g)
			if got := history.LoadURLTestHistory("node"); got == nil || got.Delay != want {
				t.Fatal("host-owned refresh inherited canceled manual publication guard")
			}
			if g.selected().tcp != g.outbounds[0] || g.selected().udp != g.outbounds[0] || calls.Load() != wantCalls {
				t.Fatal("host-owned refresh did not publish selection exactly once per pass")
			}
		})
	}
}

func TestManualCancellationDuringSelectionSnapshotRejectsPublication(t *testing.T) {
	g, history, _ := epochTestGroup(t)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	g.outbounds = []adapter.Outbound{&blockingNetworkOutbound{
		epochTestOutbound: epochTestOutbound{tag: "node"},
		entered:          entered,
		release:          release,
	}}
	epoch := history.Epoch()
	if !history.StoreIfCurrent(epoch, "node", &adapter.URLTestHistory{Delay: 5}) {
		t.Fatal("initial history unavailable")
	}
	caller := &pendingURLTestCancelContext{Context: context.Background(), done: make(chan struct{})}
	defer caller.cancel()
	go func() {
		g.performUpdateCheckEpochContext(caller, epoch)
		close(finished)
	}()
	awaitEpochSignal(t, entered)
	caller.cancel()
	once.Do(func() { close(release) })
	awaitEpochSignal(t, finished)
	if g.selection.Load() != nil {
		t.Fatal("canceled caller published a previously captured selection snapshot")
	}
}
