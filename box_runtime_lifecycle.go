package box

import (
	"context"
	"errors"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"
)

func (s *Box) runtimeStableStage(stage adapter.StartStage) error {
	scope := s.runtime.stable.scope
	if stage != adapter.StartStateStarted {
		for _, internal := range s.internalService {
			if err := scope.Start(internal.Name(), internal, stage); err != nil {
				return err
			}
		}
	}
	for _, component := range []boxComponent{{"network", s.network}, {"connection", s.connection}} {
		if err := scope.Start(component.name, component.lifecycle, stage); err != nil {
			return err
		}
	}
	return nil
}

func (s *Box) preStartRuntime() error {
	c := s.runtime
	c.access.Lock()
	if c.initialPhase >= 1 {
		c.access.Unlock()
		return nil
	}
	if c.stopped || c.preparing {
		c.access.Unlock()
		return errors.New("runtime startup unavailable")
	}
	c.preparing = true
	c.workDone = make(chan struct{})
	c.access.Unlock()
	succeeded := false
	defer func() {
		c.access.Lock()
		c.preparing = false
		close(c.workDone)
		if succeeded {
			c.initialPhase = 1
		}
		c.access.Unlock()
	}()
	if err := s.logFactory.Start(); err != nil {
		return err
	}
	c.stable.scope.Add(s.logFactory.Close)
	applyDebugOptions(s.debugOptions)
	debugServer, err := startDebugHTTPServer(s.debugOptions)
	if err != nil {
		return err
	}
	if debugServer != nil {
		c.stable.scope.Add(debugServer.Close)
	}
	for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart} {
		if err := s.runtimeStableStage(stage); err != nil {
			return err
		}
		if err := s.startRuntimeGraphStage(c.initialPrepared, stage); err != nil {
			return err
		}
	}
	succeeded = true
	return nil
}

func (s *Box) startRuntime() error {
	if err := s.preStartRuntime(); err != nil {
		return err
	}
	c := s.runtime
	c.access.Lock()
	if c.initialPhase == 2 {
		c.access.Unlock()
		return nil
	}
	if c.stopped || c.preparing {
		c.access.Unlock()
		return errors.New("runtime startup unavailable")
	}
	c.preparing = true
	c.workDone = make(chan struct{})
	c.access.Unlock()
	defer func() { c.access.Lock(); c.preparing = false; close(c.workDone); c.access.Unlock() }()
	for _, stage := range []adapter.StartStage{adapter.StartStatePostStart, adapter.StartStateStarted} {
		if err := s.startRuntimeGraphStage(c.initialPrepared, stage); err != nil {
			return err
		}
		if err := s.runtimeStableStage(stage); err != nil {
			return err
		}
	}
	if err := c.reference.Start(adapter.StartStateStarted, c.stable.scope); err != nil {
		return err
	}
	prepared := c.initialPrepared
	var endpointErr error
	prepared.endpointTransaction, endpointErr = s.stageRuntimeEndpoints(c.ctx, prepared)
	if endpointErr != nil {
		return endpointErr
	}
	if err := s.sealRuntimeGraph(prepared); err != nil {
		return err
	}
	if err := runtimeCheckSources(c.ctx, c.initialSources); err != nil {
		return err
	}
	if err := prepared.stageRuntimeCertificates(c.ctx); err != nil {
		return err
	}
	if err := s.prepareRuntimePostBindEffects(c.ctx, prepared); err != nil {
		return err
	}
	if err := s.stageRuntimeTun(c.ctx, prepared, false); err != nil {
		return err
	}
	if err := s.stageRuntimeListeners(c.ctx, prepared, false); err != nil {
		return err
	}
	if err := prepared.stageRuntimePostBindEffects(c.ctx); err != nil {
		return err
	}
	commit, err := prepared.fenceRuntimeFakeIP()
	if err != nil {
		return err
	}
	if err := prepared.endpointTransaction.PreparePublication(); err != nil {
		return err
	}
	publication := runtimeFakeIPPublication{logPublication: prepared.logPublication, commit: commit, dnsStores: prepared.dnsStores, endpoints: prepared.endpointTransaction}
	defer func() { publication.abort() }()
	if prepared.tunTransaction != nil {
		publication.tun, err = prepared.tunTransaction.PreparePublication()
		if err != nil {
			return err
		}
	}
	if prepared.listenerTransaction != nil {
		publication.listeners, err = prepared.listenerTransaction.PreparePublication()
		if err != nil {
			return err
		}
	}
	c.access.Lock()
	if c.stopped {
		c.access.Unlock()
		return errors.New("runtime stopped during startup")
	}
	_, err = publication.publish(c.store, c.active.graphRevision(), prepared.graph)
	if err == nil {
		prepared.published = true
		c.resources = append([]*runtimeResource(nil), prepared.resources...)
		c.rootDigest = prepared.rootDigest
		c.tunDependencies = prepared.tunDependencies
		for _, resource := range prepared.resources {
			resource.networkReady = true
		}
		c.active = RuntimeIdentity{Incarnation: prepared.view.identity.Incarnation, Revision: prepared.view.identity.Revision, EffectiveDigest: runtimeDigest(c.canonical)}
	}
	c.access.Unlock()
	if err != nil {
		return err
	}
	if prepared.fakeIPMigration != nil {
		prepared.fakeIPMigration.ActivatePersistence()
	}
	service.PtrFromContext[urltest.HistoryStorage](c.ctx).SetRuntimeActiveHistories(prepared.view.runtimeActiveHistories())
	prepared.releaseConstruction()
	for _, activate := range prepared.activate {
		activate()
	}
	if err := c.reference.Activate(); err != nil {
		return err
	}
	// Graph admission is ready before external API/listener work can enter.
	for _, internal := range s.internalService {
		if err := c.stable.scope.Start(internal.Name(), internal, adapter.StartStateStarted); err != nil {
			return err
		}
	}
	// Graph admission is ready before listeners can accept their first flow.
	for _, stage := range adapter.ListStartStages {
		if err := c.ingressScope.Start("inbound", s.inbound, stage); err != nil {
			return err
		}
	}
	c.access.Lock()
	c.platformRequirements = c.initialRouter.RuntimeProvisionedRequirements(c.platformRequirements)
	c.initialPhase = 2
	c.access.Unlock()
	return nil
}

// This outer-scope cleanup seals admission and cancels producer roots. Stable
// OS/process dependencies close only when every dependent resource has actually
// drained. An observation timeout retains the catalog and reports uncertainty.
func (s *Box) closeRuntimeResources() error {
	ctx, cancel := context.WithTimeout(context.Background(), C.StopTimeout)
	defer cancel()
	return runtimeCleanupResult(s.closeRuntimeResourcesContext(ctx))
}

var errRuntimeCleanupIncomplete = errors.New("runtime resource cleanup remains unconfirmed")

// Scope.Close deliberately filters closed/canceled errors, including deadline
// errors. An observer deadline is not successful resource cleanup. Preserve a
// non-filterable sentinel as a separate multi-error member. Scope.Close expands
// members before filtering cancellation, while ordinary causes retain errors.Is.
func runtimeCleanupResult(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", errRuntimeCleanupIncomplete, err)
}

// Observer cancellation never cancels the independently owned cleanup.
func (s *Box) closeRuntimeResourcesContext(ctx context.Context) error {
	c := s.runtime
	c.shutdownOnce.Do(func() {
		// Seal observer admission before the graph store. A just-admitted
		// census can then distinguish shutdown from a broken current view.
		if c.reference != nil {
			c.reference.Stop()
		}
		c.access.Lock()
		c.stopped = true
		c.store.Seal()
		var workDone <-chan struct{}
		if c.preparing {
			workDone = c.workDone
		}
		c.access.Unlock()
		go func() {
			if workDone != nil {
				<-workDone
			}
			c.access.Lock()
			resources := make([]*runtimeResource, 0, len(c.catalog))
			for _, resource := range c.catalog {
				resources = append(resources, resource)
			}
			initial := c.initialPrepared
			pending := c.pendingPrepared
			reservation := c.stableReservation
			c.stableReservation = nil
			c.access.Unlock()
			if c.reference != nil {
				c.reference.Stop()
			}
			if initial != nil {
				initial.abort()
			}
			if pending != nil && pending != initial {
				pending.abort()
			}
			for _, resource := range resources {
				if resource.stop != nil {
					resource.stop()
				}
				if resource.stopFinal != nil {
					resource.stopFinal()
				}
				resource.owner.Seal()
			}
			if s.connection != nil {
				s.connection.CloseAll()
			}
			// Stop accepting and drain TUN flows before waiting for graph leases.
			// Waiting for the stable owner first would create a TUN-flow cycle.
			ingressErr := c.closeIngress()
			var referenceErr error
			if c.reference != nil {
				referenceErr = c.reference.WaitStopped(context.Background())
			}
			if referenceErr == nil {
				c.access.Lock()
				referenceReservation := c.referenceReservation
				c.referenceReservation = nil
				c.access.Unlock()
				if referenceReservation != nil {
					referenceReservation.Release()
				}
			}
			if ingressErr != nil || referenceErr != nil {
				// Keep the original stable reservation charged on uncertainty.
				c.access.Lock()
				c.stableReservation = reservation
				c.access.Unlock()
				c.shutdownError = errors.Join(ingressErr, referenceErr)
			} else {
				if reservation != nil {
					reservation.Release()
				}
				c.shutdownError = waitRuntimeResources(context.Background(), resources)
			}
			close(c.shutdownDone)
		}()
	})
	select {
	case <-c.shutdownDone:
		return c.shutdownError
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *runtimeCoordinator) closeIngress() error {
	c.ingressCloseOnce.Do(func() {
		if c.ingressScope != nil {
			c.ingressCloseError = c.ingressScope.Close()
		}
	})
	return c.ingressCloseError
}
