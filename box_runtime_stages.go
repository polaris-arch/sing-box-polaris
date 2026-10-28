package box

import (
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
)

// Each owned component receives its resource scope, including on partial start.
// Borrowed components never receive another lifecycle call. A failed stage is
// terminal for this candidate and its caller must abort the owned closure.
func (s *Box) startRuntimeGraphStage(g *preparedRuntimeGraph, stage adapter.StartStage) error {
	if int(stage) >= len(g.stages) {
		return errors.New("invalid runtime lifecycle stage")
	}
	if g.stages[stage] {
		return errors.New("runtime lifecycle stage already attempted")
	}
	g.stages[stage] = true
	startLeaves := func() error {
		// Route platform/rule setup precedes DNS rule startup, independently of
		// SCC map iteration order. Both use their original resource scope.
		for _, name := range []string{"route-router", "dns-router"} {
			for _, resource := range g.created {
				component := resource.components[name]
				if component == nil {
					continue
				}
				if component.router != nil {
					if err := resource.scope.Start("runtime router", component.router, stage); err != nil {
						return err
					}
				}
				if component.dns != nil {
					if err := resource.scope.Start("runtime DNS router", component.dns, stage); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if stage == adapter.StartStateInitialize {
		if g.fakeIPMigration != nil {
			if err := g.fakeIPMigration.InitializePersistentStorage(s.runtime.ctx); err != nil {
				return err
			}
		}
		for _, stores := range g.dnsStores {
			if err := stores.Prepare(); err != nil {
				return err
			}
		}
		if err := startLeaves(); err != nil {
			return err
		}
	}
	if g.endpointManager != nil {
		if err := g.endpointManager.Start(stage, nil); err != nil {
			return err
		}
	}
	if err := g.outboundManager.Start(stage, nil); err != nil {
		return err
	}
	if err := g.transportManager.Start(stage, nil); err != nil {
		return err
	}
	if stage == adapter.StartStateStart {
		for _, resource := range g.created {
			if resource.sourceProducer != nil {
				if err := resource.sourceProducer.start(); err != nil {
					return err
				}
			}
		}
		startContext := adapter.NewHTTPStartContext()
		defer startContext.Close()
		for _, resource := range g.created {
			for _, component := range resource.components {
				if component.ruleSet != nil {
					if err := component.ruleSet.StartContext(resource.scope.Context(), startContext); err != nil {
						return err
					}
				}
			}
		}
	}
	if g.certificateManager != nil {
		if err := g.certificateManager.Start(stage, nil); err != nil {
			return err
		}
	}
	if g.serviceManager != nil {
		if err := g.serviceManager.Start(stage, nil); err != nil {
			return err
		}
	}
	if g.inboundManager != nil {
		if err := g.inboundManager.Start(stage, nil); err != nil {
			return err
		}
	}
	if stage != adapter.StartStateInitialize {
		if err := startLeaves(); err != nil {
			return err
		}
	}
	if stage == adapter.StartStateStarted {
		for _, resource := range g.created {
			for _, component := range resource.components {
				if component.clock != nil {
					if err := component.clock.Prepare(); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (s *Box) sealRuntimeGraph(g *preparedRuntimeGraph) error {
	if g.graph != nil {
		return errors.New("runtime graph already sealed")
	}
	g.effectAccess.Lock()
	g.effectRegistrationClosed = true
	g.effectAccess.Unlock()
	for _, started := range g.stages {
		if !started {
			return errors.New("runtime lifecycle incomplete")
		}
	}
	graph, err := runtimegraph.NewGraph(g.view, g.construction)
	if err != nil {
		return err
	}
	g.graph = graph
	return nil
}
