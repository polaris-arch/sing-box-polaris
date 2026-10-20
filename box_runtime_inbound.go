package box

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter/inbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
)

func runtimeResourceListeners(resources []*runtimeResource) []*listener.Listener {
	var result []*listener.Listener
	for _, resource := range resources {
		for _, component := range resource.components {
			if value, ok := component.inbound.(inbound.RuntimePreparedInbound); ok {
				result = append(result, value.RuntimeListeners()...)
			}
			if value, ok := component.service.(boxService.RuntimePreparedService); ok {
				result = append(result, value.RuntimeListeners()...)
			}
		}
	}
	return result
}

// Stage pauses only replaced/removed ingress. Retained listeners continue to
// admit against the stable current-graph gateway. All physical bind effects
// precede publication and remain owned by the compensation record on failure.
func (s *Box) stageRuntimeListeners(ctx context.Context, g *preparedRuntimeGraph, allowReconnect bool) error {
	current := make(map[*runtimeResource]bool, len(g.resources))
	for _, r := range g.resources {
		current[r] = true
	}
	s.runtime.access.Lock()
	old := append([]*runtimeResource(nil), s.runtime.resources...)
	s.runtime.access.Unlock()
	var replaced, retained []*runtimeResource
	for _, r := range old {
		if current[r] {
			retained = append(retained, r)
		} else {
			replaced = append(replaced, r)
		}
	}
	previous := runtimeResourceListeners(replaced)
	next := runtimeResourceListeners(g.created)
	if len(previous) == 0 && len(next) == 0 {
		return nil
	}
	// Include unchanged occupancy in validation, without pausing its ingress.
	all := append(runtimeResourceListeners(retained), next...)
	if _, err := listener.PlanListenerSet(nil, all); err != nil {
		return err
	}
	transaction, err := listener.ReserveListenerSet(previous, next, allowReconnect)
	if err != nil {
		return err
	}
	g.listenerTransaction = transaction
	return transaction.Stage(ctx)
}

func (g *preparedRuntimeGraph) restoreRuntimeListeners() error {
	return g.restoreRuntimeListenersWithEffects(true)
}

func (g *preparedRuntimeGraph) restoreRuntimeListenersWithEffects(candidateAbsent bool) error {
	if g == nil || g.listenerRestoration != nil {
		return nil
	}
	restoreEffects := func() error {
		if !candidateAbsent {
			return errors.New("candidate registration absence remains unknown")
		}
		g.restoreRuntimePreviousEffects()
		return g.postBindError
	}
	if g.listenerTransaction == nil {
		return restoreEffects()
	}
	restoration := g.listenerTransaction.CompensateBeforeActivate(restoreEffects)
	g.listenerRestoration = &restoration
	if !restoration.Restored {
		if restoration.Error != nil {
			return restoration.Error
		}
		return errors.New("previous listener restoration remains unconfirmed")
	}
	return nil
}

func runtimeAcceptedListenerReconnect(impacts []RuntimeImpact) bool {
	for _, impact := range impacts {
		if (impact.Path == "inbounds" || impact.Path == "services" || impact.Path == "endpoints") && impact.ReconnectRequired {
			return true
		}
	}
	return false
}

func (s *Box) recordRuntimeListenerRestoration(record *runtimePlanRecord, g *preparedRuntimeGraph) {
	if g.listenerRestoration == nil {
		return
	}
	restoration := g.listenerRestoration
	s.runtime.access.Lock()
	defer s.runtime.access.Unlock()
	if !restoration.Restored {
		record.operation.Errors = append(record.operation.Errors, RuntimePlanError{Code: "LISTENER_RESTORATION_FAILED", Path: "inbounds", Message: "candidate unpublished; previous physical ingress could not be fully restored"})
	}
	if restoration.LocalReconnect {
		record.operation.Errors = append(record.operation.Errors, RuntimePlanError{Code: "LISTENER_RECONNECT_REQUIRED", Path: "inbounds", Message: "candidate unpublished; local socket handoff interrupted affected sessions"})
	}
}
