package box

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	protocolWG "github.com/sagernet/sing-box/protocol/wireguard"
)

// This transaction owns only newly constructed userspace children. Old children
// remain runnable until normal graph retirement; no daily edit resets them.
type runtimeEndpointTransaction struct {
	clients     runtimeClientEndpointTransaction
	tailscale   *runtimeTailscaleEndpointTransaction
	next        []*protocolWG.Endpoint
	reserved    []*protocolWG.Endpoint
	publication *protocolWG.RuntimeEndpointPublication
	published   bool
}

type runtimeEndpointRestartRequiredError struct{ detail RuntimePlanError }

func (e *runtimeEndpointRestartRequiredError) Error() string { return e.detail.Message }

func (e *runtimeEndpointRestartRequiredError) RuntimePlanError() RuntimePlanError { return e.detail }

func runtimeEndpointRestart(tag, message string) error {
	return &runtimeEndpointRestartRequiredError{RuntimePlanError{Code: "RESTART_REQUIRED", Path: "endpoints." + tag, Message: message}}
}

func runtimeWireGuardParticipants(resources []*runtimeResource) []*protocolWG.Endpoint {
	var result []*protocolWG.Endpoint
	seen := make(map[*protocolWG.Endpoint]bool)
	for _, resource := range resources {
		for _, component := range resource.components {
			if value, ok := component.endpoint.(*protocolWG.Endpoint); ok && !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	return result
}

// Call after logical construction and before graph sealing. Even on failure,
// retain the returned transaction and candidate owners until cleanup joins.
func (s *Box) stageRuntimeEndpoints(ctx context.Context, g *preparedRuntimeGraph) (*runtimeEndpointTransaction, error) {
	t := &runtimeEndpointTransaction{next: runtimeWireGuardParticipants(g.created), clients: runtimeClientEndpointTransaction{next: runtimeClientEndpointParticipants(g.created)}}
	s.runtime.access.Lock()
	s.runtime.pruneRuntimeCatalogLocked()
	current := append([]*runtimeResource(nil), s.runtime.resources...)
	created := make(map[*runtimeResource]bool, len(g.created))
	for _, resource := range g.created {
		created[resource] = true
	}
	var retained []*runtimeResource
	for _, resource := range s.runtime.catalog {
		if !created[resource] && resource.networkReady {
			retained = append(retained, resource)
		}
	}
	s.runtime.access.Unlock()
	old := runtimeWireGuardParticipants(current)
	byTag := make(map[string]*protocolWG.Endpoint, len(old))
	for _, value := range old {
		byTag[value.Tag()] = value
	}
	// Check the entire collision set before opening any socket. A fixed port can
	// collide with a draining owner, even when that owner is absent from g.resources.
	ports := make(map[uint16]bool)
	for _, value := range runtimeWireGuardParticipants(retained) {
		_, _, port := value.RuntimePhysicalIdentity()
		if port != 0 {
			ports[port] = true
		}
	}
	for _, value := range t.next {
		if err := value.RuntimeValidate(); err != nil {
			return t, err
		}
		system, name, port := value.RuntimePhysicalIdentity()
		if system {
			return t, runtimeEndpointRestart(value.Tag(), "system WireGuard devices require restart")
		}
		if prior := byTag[value.Tag()]; prior != nil {
			previousSystem, previousName, _ := prior.RuntimePhysicalIdentity()
			if previousSystem || name != previousName {
				return t, runtimeEndpointRestart(value.Tag(), "WireGuard device identity changes require restart")
			}
		}
		if port != 0 {
			if ports[port] {
				return t, runtimeEndpointRestart(value.Tag(), "WireGuard fixed listen-port overlap requires restart")
			}
			ports[port] = true
		}
	}
	for _, value := range t.next {
		if err := ctx.Err(); err != nil {
			return t, err
		}
		// Record before entering the original reservation method, including a panic.
		t.reserved = append(t.reserved, value)
		if err := value.RuntimeReservePhysical(ctx); err != nil {
			return t, err
		}
	}
	for _, value := range t.next {
		if err := value.RuntimeStagePhysical(ctx); err != nil {
			return t, err
		}
	}
	if err := t.clients.stage(ctx); err != nil {
		return t, err
	}
	var err error
	t.tailscale, err = s.stageRuntimeTailscaleEndpoints(ctx, g, current, retained)
	if err != nil {
		return t, err
	}
	return t, nil
}

func (t *runtimeEndpointTransaction) PreparePublication() error {
	if t == nil {
		return nil
	}
	publication, err := protocolWG.PrepareRuntimeEndpointPublication(t.next)
	if err != nil {
		return err
	}
	t.publication = publication
	if err = t.clients.preparePublication(); err != nil {
		return err
	}
	return t.tailscale.preparePublication()
}

// Publish is called only after PreparePublication succeeds and inside the
// existing graph commit critical section. It performs RAM stores only.
func (t *runtimeEndpointTransaction) Publish() {
	if t == nil {
		return
	}
	t.publication.Publish()
	for _, publish := range t.clients.publish {
		publish()
	}
	t.tailscale.publish()
	t.published = true
}

func (t *runtimeEndpointTransaction) Compensate(ctx context.Context) error {
	if t == nil || t.published {
		return nil
	}
	var result error
	result = errors.Join(result, t.tailscale.compensate(ctx))
	result = errors.Join(result, t.clients.compensate(ctx))
	// Terminal close joins an outstanding Stage operation, including a caller
	// timeout. It cannot report completion merely because ctx was cancelled.
	for _, value := range slices.Backward(t.next) {
		result = errors.Join(result, value.RuntimeCloseAndWait())
	}
	for _, value := range slices.Backward(t.reserved) {
		result = errors.Join(result, value.RuntimeReleasePhysicalReservation(ctx))
	}
	if result != nil {
		return tls.NewRuntimeCleanupError(result)
	}
	return nil
}

// preflightRuntimeEndpoints performs no native operations. A concurrent
// construction has no immutable endpoint census yet, so only published owners
// enter the census. Stage repeats all physical collision checks.
func (s *Box) preflightRuntimeEndpoints(ctx context.Context, options option.Options, intents []RuntimeSelectorIntent, rootDigest [32]byte) error {
	if err := s.preflightRuntimeTailscaleEndpoints(ctx, options, intents, rootDigest); err != nil {
		return err
	}
	hasWireGuard, needsPortCensus := false, false
	for _, input := range options.Endpoints {
		if input.Type == C.TypeWireGuard {
			hasWireGuard = true
			if value, ok := input.Options.(*option.WireGuardEndpointOptions); ok && value.ListenPort != 0 {
				needsPortCensus = true
			}
		}
	}
	if !hasWireGuard {
		return nil
	}
	c := s.runtime
	c.access.Lock()
	c.pruneRuntimeCatalogLocked()
	current := append([]*runtimeResource(nil), c.resources...)
	var retained []*runtimeResource
	for _, resource := range c.catalog {
		if !needsPortCensus {
			break
		}
		if !resource.networkReady {
			continue
		}
		retained = append(retained, resource)
	}
	c.access.Unlock()
	replace, err := runtimeReplacementNames(ctx, options, intents, rootDigest, current)
	if err != nil {
		return err
	}
	priorByTag := make(map[string]*protocolWG.Endpoint)
	for _, value := range runtimeWireGuardParticipants(current) {
		priorByTag[value.Tag()] = value
	}
	ports := make(map[uint16]bool)
	for _, value := range runtimeWireGuardParticipants(retained) {
		_, _, port := value.RuntimePhysicalIdentity()
		if port != 0 {
			ports[port] = true
		}
	}
	for index, input := range options.Endpoints {
		if input.Type != C.TypeWireGuard {
			continue
		}
		tag := input.Tag
		if tag == "" {
			tag = fmt.Sprint(index)
		}
		value, ok := input.Options.(*option.WireGuardEndpointOptions)
		if !ok {
			return errors.New("invalid WireGuard endpoint options")
		}
		if value.System {
			return runtimeEndpointRestart(tag, "system WireGuard devices require restart")
		}
		if prior := priorByTag[tag]; prior != nil {
			system, name, _ := prior.RuntimePhysicalIdentity()
			if system || name != value.Name {
				return runtimeEndpointRestart(tag, "WireGuard device identity changes require restart")
			}
		}
		if !replace["endpoint:"+tag] {
			continue
		}
		if value.ListenPort != 0 {
			if ports[value.ListenPort] {
				return runtimeEndpointRestart(tag, "WireGuard fixed listen-port overlap requires restart")
			}
			ports[value.ListenPort] = true
		}
	}
	return nil
}
