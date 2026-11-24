package wireguard

import (
	"context"
	"net"
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

type probeDialPath struct{ parent *probeDialPath }

type probeActivation struct {
	device    *device.Device
	ctx       context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	done      chan struct{}
	phase     atomic.Uint32
	path      *probeDialPath
	borrowers int // protected by Endpoint.stateAccess
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
	probe := e.probe.Load()
	if probe == nil {
		return !e.options.StartSuspended || !e.suspended.Load()
	}
	return probe.promote()
}

func (probe *probeActivation) promote() bool {
	return probe.phase.CompareAndSwap(probeBorrowed, probePromoted) || probe.phase.Load() == probePromoted
}

func (e *Endpoint) lockState(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		e.stateAccess.Lock()
		probe := e.probe.Load()
		if probe == nil || e.device.Load() == nil {
			return nil
		}
		var wait <-chan struct{}
		switch probe.phase.Load() {
		case probeOpening:
			wait = probe.ready
		case probeRetiring:
			wait = probe.done
		default:
			return nil
		}
		e.stateAccess.Unlock()
		// A keepalive can resolve or detour through the device it is opening.
		for path, _ := ctx.Value(probeDialPathKey{}).(*probeDialPath); path != nil; path = path.parent {
			if path == probe.path {
				return net.ErrClosed
			}
		}
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (e *Endpoint) acquireFlow(ctx context.Context) (func(), error) {
	if !e.options.StartSuspended || !urltest.IsBackgroundProbe(ctx) {
		return nil, e.resume(ctx)
	}
	if err := e.lockState(ctx); err != nil {
		return nil, err
	}
	wgDevice := e.device.Load()
	if wgDevice == nil {
		e.stateAccess.Unlock()
		return nil, net.ErrClosed
	}
	if probe := e.probe.Load(); probe != nil && probe.phase.Load() == probeBorrowed {
		probe.borrowers++
		e.stateAccess.Unlock()
		return func() { e.releaseProbe(probe) }, nil
	}
	if !e.suspended.Load() || e.returnAttached.Load() {
		err := e.resumeLocked(wgDevice)
		e.stateAccess.Unlock()
		return nil, err
	}
	if e.networkPaused {
		e.stateAccess.Unlock()
		return nil, urltest.ErrProbeNotRun
	}
	parent, _ := ctx.Value(probeDialPathKey{}).(*probeDialPath)
	probe := &probeActivation{
		device: wgDevice, ready: make(chan struct{}), done: make(chan struct{}),
		path: &probeDialPath{parent: parent}, borrowers: 1,
	}
	probeContext := context.WithValue(e.options.Context, probeDialPathKey{}, probe.path)
	probeContext = urltest.ContextWithSharedBackgroundProbe(probeContext, func(func(context.Context) bool) bool {
		return probe.phase.Load() <= probeBorrowed
	})
	probe.ctx, probe.cancel = context.WithCancel(probeContext)
	e.probe.Store(probe)
	e.stateAccess.Unlock()
	defer close(probe.ready)

	stop := context.AfterFunc(ctx, probe.cancel)
	err := wgDevice.Up()
	if !stop() {
		probe.cancel()
	}
	e.stateAccess.Lock()
	if e.device.Load() != wgDevice {
		e.stateAccess.Unlock()
		return nil, net.ErrClosed
	}
	if err != nil {
		e.probe.Store(nil)
		probe.cancel()
		e.stateAccess.Unlock()
		return nil, err
	}
	if e.networkPaused || probe.ctx.Err() != nil {
		e.retireProbeLocked(probe, true)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, urltest.ErrProbeNotRun
	}
	e.suspended.Store(false)
	probe.phase.Store(probeBorrowed)
	e.stateAccess.Unlock()
	return func() { e.releaseProbe(probe) }, nil
}

func (e *Endpoint) releaseProbe(probe *probeActivation) {
	e.stateAccess.Lock()
	if e.probe.Load() == probe && e.device.Load() == probe.device {
		probe.borrowers--
		if probe.borrowers == 0 && probe.phase.CompareAndSwap(probeBorrowed, probeRetiring) {
			e.retireProbeLocked(probe, true)
			return
		}
	}
	e.stateAccess.Unlock()
}

// retireProbeLocked consumes stateAccess. Keep the old owner visible until
// Down has joined its native workers, without holding their admission lock.
func (e *Endpoint) retireProbeLocked(probe *probeActivation, suspended bool) {
	probe.phase.Store(probeRetiring)
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
