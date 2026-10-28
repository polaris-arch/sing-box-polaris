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

// A failed TryLock only reports contention, including another test callback
// or setup completion. Prove actual reentry while Close is still active instead.
type finalManagerReentryProbe struct {
	started chan struct{}
	done    chan struct{}
	err     error // published by closing done
}

func newFinalManagerReentryProbe(m *ConnectionManager) *finalManagerReentryProbe {
	probe := &finalManagerReentryProbe{started: make(chan struct{}), done: make(chan struct{})}
	go func() {
		close(probe.started)
		done, err := m.reserveFlowTask(context.Background())
		if done != nil {
			done()
			err = errors.Join(err, errors.New("unexpected reentry task admitted"))
		}
		probe.err = err
		close(probe.done)
	}()
	return probe
}

func (p *finalManagerReentryProbe) wait(ctx context.Context) error {
	select {
	case <-p.done:
		return p.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestFinalLogicalFlowReentryProbeRejectsHeldManagerLock(t *testing.T) {
	m := finalManager()
	m.StopFinal()
	var probe *finalManagerReentryProbe
	var observed error
	closer := &finalTestCloser{check: func() {
		probe = newFinalManagerReentryProbe(m)
		managerAwait(t, probe.started)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		// Hold access across the entire observation. A probe that ignores
		// manager reentry must return early and fail this negative control.
		observed = probe.wait(ctx)
		select {
		case <-probe.done:
			t.Error("reentry completed while Close caller held manager lock")
		default:
		}
	}}
	func() {
		m.access.Lock()
		defer m.access.Unlock()
		_ = closer.Close()
	}()
	managerAwait(t, probe.done)
	if observed != context.DeadlineExceeded {
		t.Fatalf("held manager lock accepted: %v", observed)
	}
	if probe.err != net.ErrClosed {
		t.Fatalf("released probe did not join sealed manager: %v", probe.err)
	}
	if err := finalAwaitClose(t, m); err != nil {
		t.Fatal(err)
	}
}

func TestFinalLogicalFlowReentryProbeRejectsUnsealedAdmission(t *testing.T) {
	m := finalManager()
	probe := newFinalManagerReentryProbe(m)
	managerAwait(t, probe.done)
	if probe.err == nil || probe.err == net.ErrClosed {
		t.Fatalf("unsealed task admission accepted: %v", probe.err)
	}
	if m.diagnosticTasks.Load() != 0 {
		t.Fatal("unexpected admission task was not returned")
	}
	if err := finalAwaitClose(t, m); err != nil {
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
	probes := make(chan *finalManagerReentryProbe, 2)
	var observedProbes []*finalManagerReentryProbe
	check := func() {
		probe := newFinalManagerReentryProbe(m)
		probes <- probe
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := probe.wait(ctx); err != net.ErrClosed {
			t.Errorf("Close cannot reenter sealed manager: %v", err)
		}
	}
	a.check = check
	b.check = check
	_, f, setup := finalFlow(t, m, a)
	f.replace(1, b)
	m.StopFinal()
	setup()
	defer func() {
		// Also retire owned workers when a deliberately bad join returns early.
		release()
		done := make(chan struct{})
		go func() { m.tasks.Wait(); close(done) }()
		managerAwait(t, done)
		// No counted callback can publish another helper after the join.
		close(probes)
		for probe := range probes {
			observedProbes = append(observedProbes, probe)
		}
		for _, probe := range observedProbes {
			managerAwait(t, probe.done)
		}
	}()
	managerAwait(t, a.entered)
	managerAwait(t, b.entered)
	// Each callback has returned from its bounded observation. Join every
	// helper even if that observation failed; a timeout is never washed out.
	for range 2 {
		probe := <-probes
		observedProbes = append(observedProbes, probe)
		managerAwait(t, probe.done)
	}
	started := make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		close(started)
		completed <- m.closeRuntimeTasks()
	}()
	managerAwait(t, started)
	// Both Close callbacks have entered, but a is still blocked on gate.
	// Observe the started waiter, not an immediate select before scheduling.
	observation := time.NewTimer(100 * time.Millisecond)
	var closeErr error
	returned := false
	select {
	case closeErr = <-completed:
		returned = true
		t.Error("blocked Close treated as completed")
	case <-observation.C:
	}
	observation.Stop()
	release()
	if !returned {
		select {
		case closeErr = <-completed:
		case <-time.After(3 * time.Second):
			t.Fatal("released final close was not joined")
		}
	}
	if closeErr != nil {
		t.Fatal(closeErr)
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
