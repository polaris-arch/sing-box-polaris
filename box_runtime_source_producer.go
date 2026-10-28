package box

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	roots "github.com/sagernet/sing-box/common/certificate"
	"github.com/sagernet/sing-box/internal/runtimegraph"

	"github.com/fsnotify/fsnotify"
)

// A watcher only submits immutable-source transactions. It never mutates the
// rules in a published graph. Its callback does no graph lookup or native I/O.
type runtimeSourceProducer struct {
	box             *Box
	ctx             context.Context
	cancel          context.CancelFunc
	watcher         *fsnotify.Watcher
	rootStore       *roots.Store
	rootChanges     <-chan struct{}
	paths           map[string]bool
	remoteIntervals map[string]time.Duration
	remoteNext      map[string]time.Time
	remoteTick      time.Duration
	eventsDone      chan struct{}
	changed         chan struct{}
	active          chan struct{}
	done            chan struct{}
	activateOnce    sync.Once
	startOnce       sync.Once
	closeOnce       sync.Once
	startErr        error
	setupCloseErr   error
	closeErr        error
	fingerprint     string
}

func (p *runtimeSourceProducer) signal() {
	select {
	case <-p.ctx.Done():
		return
	default:
	}
	select {
	case p.changed <- struct{}{}:
	default:
	}
}

func (p *runtimeSourceProducer) start() error {
	p.startOnce.Do(func() {
		if len(p.paths) > 0 {
			p.watcher, p.startErr = fsnotify.NewWatcher()
		}
		if p.startErr == nil && p.watcher != nil {
			directories := make(map[string]bool)
			for path := range p.paths {
				directories[filepath.Dir(path)] = true
			}
			for directory := range directories {
				if err := p.watcher.Add(directory); err != nil {
					p.setupCloseErr = p.watcher.Close()
					p.startErr = errors.Join(err, p.setupCloseErr)
					break
				}
			}
		}
		if p.startErr != nil {
			close(p.eventsDone)
			close(p.done)
			return
		}
		go p.events()
		go p.run()
	})
	return p.startErr
}

func (p *runtimeSourceProducer) activate() { p.activateOnce.Do(func() { close(p.active); p.signal() }) }
func (p *runtimeSourceProducer) stop()     { p.cancel() }
func (p *runtimeSourceProducer) close() error {
	p.closeOnce.Do(func() {
		p.cancel()
		// A never-started candidate still has an observable completed worker.
		p.startOnce.Do(func() { close(p.eventsDone); close(p.done) })
		if p.watcher != nil {
			p.closeErr = errors.Join(p.setupCloseErr, p.watcher.Close())
		}
		<-p.eventsDone
		<-p.done
	})
	return p.closeErr
}

// Own the event loop so Close joins its actual tail, including setup failure.
// The higher-level fswatch v0.1.2 API exposes neither a loop join nor ownership
// of the local fsnotify watcher when Add fails during its Start method.
func (p *runtimeSourceProducer) events() {
	defer close(p.eventsDone)
	var events <-chan fsnotify.Event
	var failures <-chan error
	if p.watcher != nil {
		events = p.watcher.Events
		failures = p.watcher.Errors
	}
	var ticks <-chan time.Time
	if p.remoteTick > 0 {
		timer := time.NewTicker(p.remoteTick)
		defer timer.Stop()
		ticks = timer.C
	}
	for {
		select {
		case <-p.ctx.Done():
			return
		case _, ok := <-p.rootChanges:
			if !ok {
				p.rootChanges = nil
			} else {
				p.signal()
			}
		case <-ticks:
			p.signal()
		case event, ok := <-events:
			if !ok {
				return
			}
			if p.paths[event.Name] && event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) != 0 {
				p.signal()
			}
		case _, ok := <-failures:
			if !ok {
				return
			}
			p.signal()
		}
	}
}

func (p *runtimeSourceProducer) run() {
	defer close(p.done)
	select {
	case <-p.active:
	case <-p.ctx.Done():
		return
	}
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.changed:
		}
		for {
			wait, retry := p.refresh()
			if !retry {
				break
			}
			if wait == nil {
				p.signal()
				break
			}
			select {
			case <-p.ctx.Done():
				return
			case <-wait:
			}
		}
	}
}

func (p *runtimeSourceProducer) refresh() (<-chan struct{}, bool) {
	c := p.box.runtime
	c.access.Lock()
	if c.stopped {
		c.access.Unlock()
		return nil, false
	}
	if c.preparing {
		done := c.workDone
		c.access.Unlock()
		return done, true
	}
	expected := c.active
	content := append([]byte(nil), c.canonical...)
	previous := append([]runtimeSourceSnapshot(nil), c.currentSources...)
	rootDigest := c.rootDigest
	active := false
	for _, r := range c.resources {
		if r.fingerprint == p.fingerprint {
			active = true
			break
		}
	}
	c.access.Unlock()
	if !active || p.ctx.Err() != nil {
		return nil, false
	}
	// Avoid spending plan/receipt capacity on watcher noise or startup's
	// reconciliation signal when the captured bytes are still current.
	rootsCurrent := true
	if p.rootStore != nil {
		snapshot, err := p.rootStore.Snapshot(p.ctx)
		if err != nil {
			return nil, false
		}
		rootsCurrent = snapshot.Digest() == rootDigest
		snapshot.Release()
	}
	due := make(map[string]bool)
	now := time.Now()
	for identity, interval := range p.remoteIntervals {
		next, scheduled := p.remoteNext[identity]
		if !scheduled {
			p.remoteNext[identity] = now.Add(interval)
			continue
		}
		if !now.Before(next) {
			due[identity] = true
			p.remoteNext[identity] = now.Add(interval)
		}
	}
	if len(due) == 0 && rootsCurrent && runtimeCheckSources(p.ctx, previous) == nil {
		return nil, false
	}
	const actor = "internal:runtime-source-producer"
	planContext := context.WithValue(p.ctx, runtimeSourceRefreshKey{}, due)
	plan, err := p.box.planRuntimeConfig(planContext, actor, expected, content)
	if err != nil {
		return nil, false
	}
	if !plan.Applicable {
		return nil, false
	}
	// An unchanged successful download does not consume a graph revision or
	// accumulate executable no-op plans. Only this producer's unused plan is
	// removed, under the same coordinator guard used for plan admission.
	c.access.Lock()
	record := c.plans[plan.TransactionID]
	unchanged := rootsCurrent && c.active == expected && bytes.Equal(c.canonical, content) && record != nil && record.actor == actor && !record.consumed && !record.inFlight && runtimeEqualSourceSnapshots(previous, record.sources)
	if unchanged {
		c.planStorage -= record.storageCharge
		delete(c.plans, plan.TransactionID)
	}
	c.access.Unlock()
	if unchanged {
		return nil, false
	}
	_, err = p.box.applyRuntimeConfig(p.ctx, actor, RuntimeConfigApply{
		ContractVersion: RuntimeConfigContractVersion, PlanID: plan.PlanID,
		TransactionID: plan.TransactionID, Expected: expected,
		CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest,
	})
	if err != nil {
		// A competing accepted update may have won. Reconcile using that
		// graph, never publish this watcher's stale captured configuration.
		c.access.Lock()
		changed := c.active != expected
		c.access.Unlock()
		return nil, changed
	}
	return nil, false
}

func (s *Box) prepareRuntimeSourceProducer(g *preparedRuntimeGraph, sources []runtimeSourceSnapshot) error {
	var paths []string
	var identity []byte
	remoteIntervals := make(map[string]time.Duration)
	var remoteTick time.Duration
	for _, source := range sources {
		if source.remoteURL != "" {
			interval := source.updateInterval
			if interval <= 0 {
				interval = 24 * time.Hour
			}
			remoteIntervals[source.identity] = interval
			if remoteTick == 0 || interval < remoteTick {
				remoteTick = interval
			}
			identity = append(identity, []byte(fmt.Sprintf("remote:%d:%s:%d", len(source.identity), source.identity, interval))...)
		}
		if source.path == "" {
			continue
		}
		paths = append(paths, source.path)
		identity = append(identity, []byte(fmt.Sprintf("%d:%s%d:%s", len(source.identity), source.identity, len(source.path), source.path))...)
	}
	if len(paths) == 0 && len(remoteIntervals) == 0 && g.rootResource == nil {
		return nil
	}
	if g.rootResource != nil {
		identity = append(identity, []byte(fmt.Sprintf("roots:%s:%d", g.rootResource.id.Incarnation, g.rootResource.id.Sequence))...)
	}
	fingerprint := "source-producer:" + runtimeDigest(identity)
	c := s.runtime
	c.access.Lock()
	var resource *runtimeResource
	for _, old := range c.resources {
		if old.fingerprint == fingerprint {
			resource = old
			break
		}
	}
	if resource == nil && (c.stopped || len(c.catalog) >= runtimeResourceLimit || c.resourceSequence == math.MaxUint64) {
		c.access.Unlock()
		return errors.New("source producer resource capacity exhausted")
	}
	var id adapter.RuntimeResourceID
	if resource == nil {
		c.resourceSequence++
		id = adapter.RuntimeResourceID{Incarnation: c.active.Incarnation, Sequence: c.resourceSequence}
	}
	c.access.Unlock()
	if resource == nil {
		dependency, err := c.stable.owner.Acquire()
		if err != nil {
			return err
		}
		resource = &runtimeResource{id: id, fingerprint: fingerprint, kind: "source-producer", components: make(map[string]*runtimeComponent)}
		dependencies := []adapter.RuntimeResourceLease{dependency}
		if g.rootResource != nil {
			lease, acquireErr := g.rootResource.owner.Acquire()
			if acquireErr != nil {
				dependency.Release()
				return acquireErr
			}
			dependencies = append(dependencies, lease)
		}
		resource.owner, err = runtimegraph.NewResourceOwner(c.ctx, id, dependencies, func() error { return resource.scope.Close() })
		for _, held := range dependencies {
			held.Release()
		}
		if err != nil {
			return err
		}
		resource.scope = adapter.NewScope(resource.owner.Context(), s.logger)
		g.created = append(g.created, resource)
		c.access.Lock()
		c.catalog[id] = resource
		c.access.Unlock()
		ctx, cancel := context.WithCancel(resource.scope.Context())
		p := &runtimeSourceProducer{box: s, ctx: ctx, cancel: cancel, changed: make(chan struct{}, 1), active: make(chan struct{}), done: make(chan struct{}), eventsDone: make(chan struct{}), fingerprint: fingerprint, paths: make(map[string]bool), remoteIntervals: remoteIntervals, remoteNext: make(map[string]time.Time), remoteTick: remoteTick}
		if g.rootResource != nil {
			p.rootStore = g.rootResource.rootStore
			p.rootChanges = p.rootStore.RuntimeChanges()
		}
		for _, path := range paths {
			p.paths[path] = true
		}
		resource.scope.Add(p.close)
		resource.sourceProducer = p
		resource.addRuntimeStop(p.stop, nil)
		g.activate = append(g.activate, p.activate)
	}
	reservation, err := resource.owner.Acquire()
	if err != nil {
		return err
	}
	g.construction = append(g.construction, reservation)
	g.resources = append(g.resources, resource)
	return nil
}
