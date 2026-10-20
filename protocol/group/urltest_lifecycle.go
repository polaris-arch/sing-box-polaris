package group

import (
	"context"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/service/pause"
)

type urlTestSelection struct {
	tcp adapter.Outbound
	udp adapter.Outbound
}

type groupCheckResult struct {
	values map[string]uint16
	err    error
}

// Publication must observe the effective caller even before an asynchronous
// cancellation bridge runs. Nested native checks inherit this guard; required
// and coalesced host-owned passes deliberately start from the host context.
type urlTestCallerGuardKey struct{}

func urlTestCanPublish(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	guard, loaded := ctx.Value(urlTestCallerGuardKey{}).(func() bool)
	return !loaded || guard()
}

// Check work and ticker loops reserve workers under access. Closing admission
// precedes Wait; actual raw probes, never just timed-out waiters, own the lease.
func (g *URLTestGroup) requestCheck(ctx context.Context, force, wait bool) (map[string]uint16, error) {
	return g.requestCheckEpoch(ctx, force, wait, nil)
}

func (g *URLTestGroup) requestCheckEpoch(ctx context.Context, force, wait bool, expected *urltest.HistoryEpoch) (map[string]uint16, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !urlTestCanPublish(ctx) {
		return nil, context.Canceled
	}
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return nil, os.ErrClosed
	}
	if expected != nil && !g.history.IsCurrent(expected) {
		g.access.Unlock()
		return nil, urltest.ErrStaleHistory
	}
	required := g.pendingForce
	if force {
		g.pendingForce = true
	}
	epoch := expected
	if epoch == nil {
		epoch = g.history.Epoch()
	}
	if !g.started || g.running || g.pause.IsDevicePaused() || g.pause.IsNetworkPaused() || !g.history.IsCurrent(epoch) {
		g.access.Unlock()
		return make(map[string]uint16), nil
	}
	workerContext := ctx
	if required {
		workerContext = adapter.ContextWithRuntimeOwnership(g.ctx, ctx)
	}
	// External manual probes transfer their live graph/receiver continuation
	// before the worker is published. Internal ticker/startup work is already
	// owned and joined by this resource scope, with no self-retaining root.
	release := func() {}
	_, hasGraph := adapter.RuntimeLeaseFromContext(workerContext)
	source, hasSource := adapter.RuntimeResourceSourceFromContext(g.ctx)
	hasReceiver := false
	if hasSource {
		_, hasReceiver = adapter.RuntimeResourceLeaseFromContext(workerContext, source.ID())
	}
	if hasGraph || hasReceiver {
		var retainErr error
		workerContext, release, retainErr = adapter.AcquireRuntimeOperation(workerContext, source)
		if retainErr != nil {
			g.access.Unlock()
			return nil, retainErr
		}
	}
	force = force || g.pendingForce
	g.pendingForce = false
	g.running = true
	g.workers.Add(1)
	result := make(chan groupCheckResult, 1)
	g.access.Unlock()
	go g.runChecks(workerContext, force, epoch, result, release)
	if !wait {
		return nil, nil
	}
	select {
	case result := <-result:
		return result.values, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.ctx.Done():
		return nil, g.ctx.Err()
	}
}

func (g *URLTestGroup) runChecks(caller context.Context, force bool, epoch *urltest.HistoryEpoch, result chan<- groupCheckResult, release func()) {
	defer g.workers.Done()
	defer release()
	ownership := caller
	for {
		ctx, cancel := context.WithCancel(g.ctx)
		ctx = adapter.ContextWithRuntimeOwnership(ctx, ownership)
		passCaller := caller
		ctx = context.WithValue(ctx, urlTestCallerGuardKey{}, func() bool { return urlTestCanPublish(passCaller) })
		stop := context.AfterFunc(caller, cancel)
		if caller.Err() != nil {
			cancel()
		}
		g.access.Lock()
		g.activeCancel = cancel
		if g.closed || g.pause.IsDevicePaused() || g.pause.IsNetworkPaused() {
			cancel()
		}
		g.access.Unlock()
		values := urlTestOutbounds(ctx, g.outbound, g.history, g.logger, g.outbounds, g.link, g.interval, force, epoch, g)
		current := urlTestCanPublish(ctx)
		if current {
			g.performUpdateCheckEpochContext(ctx, epoch)
		}
		current = urlTestCanPublish(ctx)
		stop()
		cancel()
		g.access.Lock()
		g.activeCancel = nil
		valid := current && urlTestCanPublish(passCaller) && !g.closed && g.history.IsCurrent(epoch)
		if !valid {
			values = make(map[string]uint16)
		}
		if result != nil {
			result <- groupCheckResult{values: values}
			result = nil
		}
		epoch = g.history.Epoch()
		if g.closed || !g.pendingForce || g.pause.IsDevicePaused() || g.pause.IsNetworkPaused() || !g.history.IsCurrent(epoch) {
			g.running = false
			g.access.Unlock()
			return
		}
		g.pendingForce = false
		g.access.Unlock()
		caller = g.ctx
		force = true
	}
}

// Called synchronously under pause.Manager's mutex. It never joins, registers,
// unregisters, probes inline, or creates one worker per coalesced request.
func (g *URLTestGroup) pauseChanged(event int) {
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return
	}
	paused := g.pause.IsDevicePaused() || g.pause.IsNetworkPaused()
	if g.ticker != nil {
		if paused {
			g.ticker.Stop()
		} else {
			g.ticker.Reset(g.interval)
		}
	}
	var cancel context.CancelFunc
	if paused {
		g.pendingForce = true
		cancel = g.activeCancel
	}
	g.access.Unlock()
	if cancel != nil {
		cancel()
	}
	if !paused && (event == pause.EventDeviceWake || event == pause.EventNetworkWake) {
		_, _ = g.requestCheck(g.ctx, true, false)
	}
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	if g.closed || g.started {
		g.access.Unlock()
		return
	}
	g.started = true
	g.lastActive.Store(time.Now())
	g.access.Unlock()
	_, _ = g.requestCheck(g.ctx, false, false)
}

func (g *URLTestGroup) Touch() {
	g.access.Lock()
	if !g.started || g.closed {
		g.access.Unlock()
		return
	}
	g.lastActive.Store(time.Now())
	if g.ticker != nil {
		g.access.Unlock()
		return
	}
	ticker := time.NewTicker(g.interval)
	if g.pause.IsDevicePaused() || g.pause.IsNetworkPaused() {
		ticker.Stop()
	}
	g.ticker = ticker
	g.workers.Add(1)
	g.access.Unlock()
	go func() { defer g.workers.Done(); g.loopCheck(ticker, g.close) }()
}

// Close requests shutdown, including before Touch. Completion is a distinct
// signal: an uncooperative probe keeps it open and cannot be treated as retired.
func (g *URLTestGroup) Close() error {
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return nil
	}
	g.closed = true
	g.pendingForce = false
	if g.ticker != nil {
		g.ticker.Stop()
		g.ticker = nil
	}
	callback := g.pauseCallback
	g.pauseCallback = nil
	close(g.close)
	g.access.Unlock()
	g.cancel()
	if callback != nil {
		g.pause.UnregisterCallback(callback)
	}
	go func() { g.workers.Wait(); close(g.done) }()
	return nil
}

func (g *URLTestGroup) Done() <-chan struct{} { return g.done }

func (g *URLTestGroup) selected() *urlTestSelection {
	selection := g.selection.Load()
	if selection == nil {
		return &urlTestSelection{}
	}
	return selection
}
