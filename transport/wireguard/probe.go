package wireguard

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/wireguard-go/device"
)

const (
	probeOpening uint32 = iota
	probeBorrowed
	probePromoted
	probeRetiring
)

type probeDialPathKey struct{}

type probeDialPath struct {
	parent     *probeDialPath // immutable ancestry for native open and close waits
	creator    atomic.Pointer[probeDialPath]
	sources    atomic.Pointer[sync.Map] // live additional dial paths and their borrow counts
	phase      atomic.Uint32
	foreground atomic.Int32
}

func (path *probeDialPath) foregroundPriority() (foreground, persistent bool) {
	shared := false
	for current := path; current != nil; current = current.creator.Load() {
		phase := current.phase.Load()
		if phase == probeRetiring {
			break
		}
		if phase == probePromoted {
			return true, true
		}
		foreground = foreground || current.foreground.Load() > 0
		shared = shared || current.sources.Load() != nil
	}
	return foreground || (shared && path.sharedForeground(nil)), false
}

// Additional borrows can transmit priority only for their own lifetime. A
// downstream lookup may revisit an active endpoint, so share one visited set.
func (path *probeDialPath) sharedForeground(visited map[*probeDialPath]bool) bool {
	for ; path != nil; path = path.creator.Load() {
		phase := path.phase.Load()
		if phase == probeRetiring || visited[path] {
			break
		}
		if phase == probePromoted || path.foreground.Load() > 0 {
			return true
		}
		if visited != nil {
			visited[path] = true
		}
		if sources := path.sources.Load(); sources != nil {
			found := false
			sources.Range(func(source, _ any) bool {
				if visited == nil {
					visited = map[*probeDialPath]bool{path: true}
				}
				found = source.(*probeDialPath).sharedForeground(visited)
				return !found
			})
			if found {
				return true
			}
		}
	}
	return false
}

// Source counts are updated under the borrowing endpoint's stateAccess.
func (path *probeDialPath) addSource(source *probeDialPath, delta int) {
	sources := path.sources.Load()
	if sources == nil {
		sources = new(sync.Map)
		sources.Store(source, delta)
		path.sources.Store(sources)
		return
	}
	next := delta
	if count, exists := sources.Load(source); exists {
		next += count.(int)
	}
	if next == 0 {
		sources.Delete(source)
	} else {
		sources.Store(source, next)
	}
}

func (path *probeDialPath) isBackground(func(context.Context) bool) bool {
	foreground, _ := path.foregroundPriority()
	return path.phase.Load() <= probeBorrowed && !foreground
}

type probeActivation struct {
	device    *device.Device
	ctx       context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	done      chan struct{}
	path      *probeDialPath
	borrowers int   // protected by Endpoint.stateAccess
	openErr   error // published by closing ready
}

func (e *Endpoint) activationContext() context.Context {
	probe := e.probe.Load()
	if probe != nil {
		return probe.ctx
	}
	return e.options.Context
}

// AdmitInbound transfers a probe's wake to accepted application traffic.
// Native receive callbacks must never wait for a joined Down.
func (e *Endpoint) AdmitInbound() bool {
	owner := e.device.Load()
	if owner == nil {
		return false
	}
	probe := e.probe.Load()
	if probe == nil {
		return (!e.options.StartSuspended || !e.suspended.Load()) && e.device.Load() == owner
	}
	return probe.promote() && e.device.Load() == owner
}

func (probe *probeActivation) promote() bool {
	return probe.path.phase.CompareAndSwap(probeBorrowed, probePromoted) || probe.path.phase.Load() == probePromoted
}

func (e *Endpoint) lockState(ctx context.Context, borrowOpening bool) error {
	parent, _ := ctx.Value(probeDialPathKey{}).(*probeDialPath)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		e.stateAccess.Lock()
		probe := e.probe.Load()
		if probe == nil || e.device.Load() == nil {
			return nil
		}
		phase := probe.path.phase.Load()
		if phase != probeOpening && phase != probeRetiring {
			return nil
		}
		// A keepalive can resolve or detour through the device it is opening.
		for path := parent; path != nil; path = path.parent {
			if path == probe.path {
				e.stateAccess.Unlock()
				return net.ErrClosed
			}
		}
		wait := probe.done
		if phase == probeOpening {
			if borrowOpening && probe.ctx.Err() == nil {
				return nil
			}
			wait = probe.ready
		}
		e.stateAccess.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// HoldProbe bridges the destination lookup and the flow's own carrier borrow.
func (e *Endpoint) HoldProbe(ctx context.Context) (func(), error) {
	return e.acquireFlow(ctx, true)
}

func (e *Endpoint) acquireFlow(ctx context.Context, probeOnly bool) (_ func(), retErr error) {
	scope := urltest.IsScopedProbe(ctx)
	parent, _ := ctx.Value(probeDialPathKey{}).(*probeDialPath)
	if probeOnly && !scope && (parent == nil || parent.phase.Load() > probeBorrowed) {
		return nil, nil
	}
	background := urltest.IsBackgroundProbe(ctx)
	inherited, persistent := parent.foregroundPriority()
	// An inherited native detour remains scoped while its priority changes.
	if !e.options.StartSuspended || (!scope && !background && (parent == nil || persistent)) {
		if probeOnly {
			return nil, nil
		}
		return nil, e.resume(ctx)
	}
	manual := scope && !background
	if err := e.lockState(ctx, manual || (inherited && !persistent)); err != nil {
		return nil, err
	}
	wgDevice := e.device.Load()
	if wgDevice == nil {
		e.stateAccess.Unlock()
		return nil, net.ErrClosed
	}
	probe := e.probe.Load()
	// WireGuard detours can become foreground while this endpoint is waiting.
	// The path contains only atomic state, so this check is safe under stateAccess.
	_, persistent = parent.foregroundPriority()
	if persistent && !scope {
		if !probeOnly && probe != nil && probe.path.phase.Load() != probeOpening {
			probe.promote()
		}
		e.stateAccess.Unlock()
		if probeOnly {
			return nil, nil
		}
		return nil, e.resume(ctx)
	}
	if probe != nil {
		phase := probe.path.phase.Load()
		if phase == probeOpening || phase == probeBorrowed {
			release := e.borrowProbeLocked(probe, manual, parent, false)
			e.stateAccess.Unlock()
			if phase == probeOpening {
				if err := e.waitForProbe(ctx, probe); err != nil {
					release()
					return nil, err
				}
			}
			return release, nil
		}
	}
	if !e.suspended.Load() || e.returnAttached {
		err := e.resumeLocked(wgDevice)
		e.stateAccess.Unlock()
		return nil, err
	}
	if e.networkPaused {
		e.stateAccess.Unlock()
		return nil, urltest.ErrProbeNotRun
	}
	probe = &probeActivation{
		device: wgDevice, ready: make(chan struct{}), done: make(chan struct{}),
		path: &probeDialPath{parent: parent},
	}
	probeContext := context.WithValue(e.options.Context, probeDialPathKey{}, probe.path)
	probeContext = urltest.ContextWithSharedBackgroundProbe(probeContext, probe.path.isBackground)
	probe.ctx, probe.cancel = context.WithCancel(probeContext)
	release := e.borrowProbeLocked(probe, manual, parent, true)
	e.probe.Store(probe)
	e.stateAccess.Unlock()
	defer close(probe.ready)
	defer func() {
		if retErr != nil {
			release()
		}
	}()

	released := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		release()
		close(released)
	})
	err := wgDevice.Up()
	if !stop() {
		<-released
	}
	e.stateAccess.Lock()
	if e.device.Load() != wgDevice {
		probe.openErr = net.ErrClosed
		e.stateAccess.Unlock()
		return nil, probe.openErr
	}
	if err != nil {
		probe.openErr = err
		e.probe.Store(nil)
		probe.cancel()
		e.stateAccess.Unlock()
		return nil, err
	}
	if e.networkPaused || probe.ctx.Err() != nil {
		probe.openErr = urltest.ErrProbeNotRun
		e.retireProbeLocked(probe, true)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, urltest.ErrProbeNotRun
	}
	e.suspended.Store(false)
	probe.path.phase.Store(probeBorrowed)
	e.stateAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return release, nil
}

func (e *Endpoint) waitForProbe(ctx context.Context, probe *probeActivation) error {
	select {
	case <-probe.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if probe.openErr != nil {
		return probe.openErr
	}
	if e.device.Load() != probe.device || e.probe.Load() != probe || probe.path.phase.Load() == probeRetiring {
		return urltest.ErrProbeNotRun
	}
	return nil
}

func (e *Endpoint) borrowProbeLocked(probe *probeActivation, foreground bool, source *probeDialPath, creator bool) func() {
	probe.borrowers++
	if foreground {
		probe.path.foreground.Add(1)
	}
	if creator {
		probe.path.creator.Store(source)
	} else if source != nil && source != probe.path {
		probe.path.addSource(source, 1)
	}
	return sync.OnceFunc(func() { e.releaseProbe(probe, foreground, source, creator) })
}

func (e *Endpoint) releaseProbe(probe *probeActivation, foreground bool, source *probeDialPath, creator bool) {
	e.stateAccess.Lock()
	if creator {
		probe.path.creator.Store(nil)
	} else if source != nil && source != probe.path {
		probe.path.addSource(source, -1)
	}
	if foreground {
		probe.path.foreground.Add(-1)
	}
	if e.probe.Load() == probe && e.device.Load() == probe.device {
		probe.borrowers--
		if probe.borrowers == 0 {
			if probe.path.phase.Load() == probeOpening {
				probe.cancel()
			} else if probe.path.phase.CompareAndSwap(probeBorrowed, probeRetiring) {
				e.retireProbeLocked(probe, true)
				return
			}
		}
	}
	e.stateAccess.Unlock()
}

// retireProbeLocked consumes stateAccess. Keep the old owner visible until
// Down has joined its native workers, without holding their admission lock.
func (e *Endpoint) retireProbeLocked(probe *probeActivation, suspended bool) {
	probe.path.phase.Store(probeRetiring)
	e.suspended.Store(suspended)
	probe.cancel()
	e.stateAccess.Unlock()
	err := probe.device.Down()
	e.stateAccess.Lock()
	e.probe.CompareAndSwap(probe, nil)
	close(probe.done)
	if !suspended && !e.networkPaused && e.device.Load() == probe.device {
		if upErr := probe.device.Up(); upErr != nil {
			e.suspended.Store(true)
			e.options.Logger.Error(upErr)
		}
	}
	e.stateAccess.Unlock()
	if err != nil {
		e.options.Logger.Error(err)
	}
}
