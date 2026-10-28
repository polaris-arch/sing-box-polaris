package route

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	outbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
)

type finalTestCloser struct {
	entered    chan struct{}
	unblock    <-chan struct{}
	once       sync.Once
	calls      atomic.Int32
	err        error
	panicClose bool
	check      func()
}

func (c *finalTestCloser) Close() error {
	c.calls.Add(1)
	if c.check != nil {
		c.check()
	}
	if c.entered != nil {
		c.once.Do(func() { close(c.entered) })
	}
	if c.unblock != nil {
		<-c.unblock
	}
	if c.panicClose {
		panic("private-test-marker")
	}
	return c.err
}
func finalManager() *ConnectionManager { return NewConnectionManager(log.NewNOPFactory().Logger()) }
func finalAwaitClose(t *testing.T, m *ConnectionManager) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- m.closeRuntimeTasks() }()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("final manager close not joined")
		return nil
	}
}

func finalFlow(t *testing.T, m *ConnectionManager, c io.Closer) (context.Context, *connectionFlow, func()) {
	t.Helper()
	ctx, f, done, err := m.reserveFlow(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, f, done
}

func TestFinalLogicalFlowSealAndLateAttach(t *testing.T) {
	m := finalManager()
	local := &finalTestCloser{}
	ctx, f, setup := finalFlow(t, m, local)
	m.StopFinal()
	if ctx.Err() == nil {
		t.Fatal("final did not cancel dial")
	}
	if _, err := m.reserveFlowTask(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late task admitted")
	}
	remote := &finalTestCloser{}
	if f.replace(1, remote) {
		t.Fatal("late remote admitted")
	}
	setup()
	if err := finalAwaitClose(t, m); err != nil {
		t.Fatal(err)
	}
	if local.calls.Load() != 1 || remote.calls.Load() != 1 {
		t.Fatal("logical side not closed exactly once")
	}
}

func TestFinalLogicalFlowCopyCompletionsAndStaleContext(t *testing.T) {
	m := finalManager()
	ctx, f, setup := finalFlow(t, m, &finalTestCloser{})
	first, err := m.reserveFlowTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.reserveFlowTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setup()
	first()
	first()
	m.access.Lock()
	_, live := m.flows[f]
	refs := f.refs
	m.access.Unlock()
	if !live || refs != 1 || ctx.Err() != nil {
		t.Fatal("first half close retired second direction")
	}
	second()
	m.access.Lock()
	_, live = m.flows[f]
	m.access.Unlock()
	if live {
		t.Fatal("actual completed flow retained")
	}
	if _, err = m.reserveFlowTask(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatal("stale flow context resurrected")
	}
	if err = finalAwaitClose(t, m); err != nil {
		t.Fatal(err)
	}
}

func TestFinalLogicalFlowParallelCloseJoinsAndDoesNotHoldLock(t *testing.T) {
	m := finalManager()
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	defer release()
	a := &finalTestCloser{entered: make(chan struct{}), unblock: gate}
	b := &finalTestCloser{entered: make(chan struct{})}
	check := func() {
		if !m.access.TryLock() {
			t.Error("arbitrary Close under manager lock")
		} else {
			m.access.Unlock()
		}
	}
	a.check = check
	b.check = check
	_, f, setup := finalFlow(t, m, a)
	f.replace(1, b)
	m.StopFinal()
	setup()
	managerAwait(t, a.entered)
	managerAwait(t, b.entered)
	completed := make(chan error, 1)
	go func() { completed <- m.closeRuntimeTasks() }()
	select {
	case <-completed:
		t.Fatal("blocked Close treated as completed")
	default:
	}
	release()
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	m.StopFinal()
	if a.calls.Load() != 1 || b.calls.Load() != 1 {
		t.Fatal("repeated final close repeated cleanup")
	}
}

func TestFinalLogicalFlowCloseErrorPanicAndUnknownPending(t *testing.T) {
	for _, closer := range []*finalTestCloser{{err: errors.New("test close failure")}, {panicClose: true}, {err: outbound.ErrRuntimeClosePending}} {
		m := finalManager()
		_, _, setup := finalFlow(t, m, closer)
		m.StopFinal()
		setup()
		if err := finalAwaitClose(t, m); err == nil {
			t.Fatal("uncertain close became success")
		}
	}
}

func TestFinalLogicalFlowRegisterSealRace(t *testing.T) {
	for range 100 {
		m := finalManager()
		start := make(chan struct{})
		done := make(chan struct{})
		local := &finalTestCloser{}
		go func() {
			defer close(done)
			<-start
			_, f, setup, err := m.reserveFlow(context.Background(), local)
			if err != nil {
				_ = local.Close()
				return
			}
			f.replace(1, &finalTestCloser{})
			setup()
		}()
		close(start)
		m.StopFinal()
		managerAwait(t, done)
		if err := finalAwaitClose(t, m); err != nil {
			t.Fatal(err)
		}
		m.access.Lock()
		flows := len(m.flows)
		m.access.Unlock()
		if flows != 0 || m.diagnosticTasks.Load() != 0 {
			t.Fatal("registration escaped final join")
		}
	}
}

func TestFinalLogicalFlowResetKeepsAdmissionAndLiveFlow(t *testing.T) {
	m := finalManager()
	local := &finalTestCloser{}
	ctx, _, setup := finalFlow(t, m, local)
	m.CloseAll()
	if ctx.Err() != nil || local.calls.Load() != 0 {
		t.Fatal("ResetNetwork cut logical flow")
	}
	task, err := m.reserveFlowTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	task()
	// Setup is still live, so final shutdown must close it, not HOT/Reset.
	m.StopFinal()
	setup()
	if err = finalAwaitClose(t, m); err != nil {
		t.Fatal(err)
	}
}

func TestFinalLogicalFlowSpliceAbortAndCompletion(t *testing.T) {
	m := finalManager()
	ctx, f, setup := finalFlow(t, m, &finalTestCloser{})
	a, b := &finalTestCloser{}, &finalTestCloser{}
	f.replace(1, b)
	callback, abort, err := m.spliceClose(ctx, a, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	abort()
	callback(errors.New("late abort callback"))
	m.access.Lock()
	refs := f.refs
	m.access.Unlock()
	if refs != 1 || a.calls.Load() != 0 {
		t.Fatal("failed splice changed setup/closed flow")
	}
	callback, _, err = m.spliceClose(ctx, a, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	setup()
	m.access.Lock()
	_, live := m.flows[f]
	m.access.Unlock()
	if !live {
		t.Fatal("installed splice not retained")
	}
	callback(nil)
	callback(nil)
	m.access.Lock()
	_, live = m.flows[f]
	m.access.Unlock()
	if live || a.calls.Load() != 1 || b.calls.Load() != 1 {
		t.Fatal("splice completion not once")
	}
	if err = finalAwaitClose(t, m); err != nil {
		t.Fatal(err)
	}
}

func TestFinalLogicalFlowDifferentManagerRejectsContext(t *testing.T) {
	m := finalManager()
	other := finalManager()
	ctx, _, setup := finalFlow(t, m, &finalTestCloser{})
	if _, err := other.reserveFlowTask(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatal("foreign manager accepted context")
	}
	setup()
	if err := finalAwaitClose(t, m); err != nil {
		t.Fatal(err)
	}
	if err := finalAwaitClose(t, other); err != nil {
		t.Fatal(err)
	}
}

type finalWrapper struct {
	io.Closer
	cleanup atomic.Int32
	err     error
}

func (w *finalWrapper) Close() error {
	err := w.Closer.Close()
	w.cleanup.Add(1)
	if w.err != nil {
		return errors.Join(err, w.err)
	}
	return err
}

func TestFinalLogicalFlowWrapperPreservesPrivateJoinAndErrors(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		raw, peer := net.Pipe()
		defer peer.Close()
		base, fence := outbound.WrapRuntimeOwnedConn(raw)
		m := finalManager()
		_, f, setup := finalFlow(t, m, &finalTestCloser{})
		f.replace(1, base)
		wrapper := &finalWrapper{Closer: base}
		if mixed {
			wrapper.err = errors.New("wrapper-owned cleanup failure")
		}
		if !f.wrap(1, wrapper) {
			t.Fatal("live wrapper rejected")
		}
		m.StopFinal()
		setup()
		err := finalAwaitClose(t, m)
		if (err != nil) != mixed {
			t.Fatalf("mixed=%v err=%v", mixed, err)
		}
		if wrapper.cleanup.Load() != 1 {
			t.Fatal("outer wrapper cleanup missing")
		}
		if err = fence.Wait(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFinalLogicalFlowLateWrappedBothSidesAreJoined(t *testing.T) {
	m := finalManager()
	a, b := &finalTestCloser{}, &finalTestCloser{}
	_, f, setup := finalFlow(t, m, a)
	f.replace(1, b)
	m.StopFinal()
	wa, wb := &finalWrapper{Closer: a}, &finalWrapper{Closer: b}
	left := f.wrap(0, wa)
	right := f.wrap(1, wb)
	if left || right {
		t.Fatal("late wrapper admitted")
	}
	setup()
	if err := finalAwaitClose(t, m); err != nil {
		t.Fatal(err)
	}
	if wa.cleanup.Load() != 1 || wb.cleanup.Load() != 1 {
		t.Fatal("late wrapper skipped by short circuit")
	}
}

func TestFinalLogicalFlowPrivateWaitPanicAndCombinedIngress(t *testing.T) {
	if err := closeFinalConnection(finalConnectionCloser{closer: &finalTestCloser{}, wait: func() error { panic("private wait marker") }}); err == nil {
		t.Fatal("wait panic became success")
	}
	a, pa := net.Pipe()
	b, pb := net.Pipe()
	defer pa.Close()
	defer pb.Close()
	ca, fa := outbound.WrapRuntimeOwnedConn(a)
	cb, fb := outbound.WrapRuntimeOwnedConn(b)
	ctx := outbound.ContextWithRuntimeInboundClose(context.Background(), ca)
	m := finalManager()
	_, _, setup, err := m.reserveFlow(ctx, cb)
	if err != nil {
		t.Fatal(err)
	}
	m.StopFinal()
	setup()
	if err = finalAwaitClose(t, m); err != nil {
		t.Fatal(err)
	}
	if err = fa.Wait(); err != nil {
		t.Fatal(err)
	}
	if err = fb.Wait(); err != nil {
		t.Fatal(err)
	}
}
