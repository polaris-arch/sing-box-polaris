//go:build with_tailscale

package box

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	protocolTS "github.com/sagernet/sing-box/protocol/tailscale"
	"github.com/sagernet/sing/service"
)

type runtimeTailscaleEndpointTransaction struct {
	next        []*protocolTS.Endpoint
	reserved    []*protocolTS.Endpoint
	publication *protocolTS.RuntimeEndpointPublication
}

func runtimeTailscaleParticipants(resources []*runtimeResource) []*protocolTS.Endpoint {
	var result []*protocolTS.Endpoint
	seen := make(map[*protocolTS.Endpoint]bool)
	for _, resource := range resources {
		for _, component := range resource.components {
			if endpoint, ok := component.endpoint.(*protocolTS.Endpoint); ok && !seen[endpoint] {
				seen[endpoint] = true
				result = append(result, endpoint)
			}
		}
	}
	return result
}

func (s *Box) stageRuntimeTailscaleEndpoints(ctx context.Context, g *preparedRuntimeGraph, current, retained []*runtimeResource) (*runtimeTailscaleEndpointTransaction, error) {
	t := &runtimeTailscaleEndpointTransaction{next: runtimeTailscaleParticipants(g.created)}
	prior := runtimeTailscaleParticipants(current)
	candidate := runtimeTailscaleParticipants(g.resources)
	fresh := make(map[*protocolTS.Endpoint]bool)
	for _, value := range t.next {
		fresh[value] = true
	}
	kept := make(map[*protocolTS.Endpoint]bool)
	for _, value := range candidate {
		if !fresh[value] {
			kept[value] = true
		}
	}
	selected := make(map[*protocolTS.Endpoint]*protocolTS.Endpoint)
	// Validate and select all physical owners before opening a new native child.
	for _, value := range t.next {
		if err := value.RuntimeValidate(); err != nil {
			return t, err
		}
		options := value.RuntimePhysicalOptions()
		var match *protocolTS.Endpoint
		for _, old := range prior {
			if !old.RuntimeCanSharePhysical(value.Tag(), options) {
				continue
			}
			if kept[old] {
				return t, runtimeEndpointRestart(value.Tag(), "Tailscale physical identity cannot have two active logical endpoints")
			}
			if match != nil && match.NATIdentity() != old.NATIdentity() {
				return t, runtimeEndpointRestart(value.Tag(), "Tailscale physical identity has ambiguous prior ownership")
			}
			match = old
		}
		selected[value] = match
	}
	// Two private candidates cannot publish different active bindings to the same
	// physical child, even when neither old logical owner survives in the graph.
	for i, value := range t.next {
		if selected[value] != nil {
			for _, other := range t.next[:i] {
				if selected[other] != nil && selected[other].NATIdentity() == selected[value].NATIdentity() {
					return t, runtimeEndpointRestart(value.Tag(), "Tailscale candidate duplicates a shared physical identity")
				}
			}
		}
	}
	for index, value := range t.next {
		for _, other := range t.next[:index] {
			overlap, err := runtimeTailscaleOptionsOverlap(s.runtime.ctx, value.RuntimePhysicalOptions(), other.RuntimePhysicalOptions())
			if err != nil {
				return t, err
			}
			if overlap {
				return t, runtimeEndpointRestart(value.Tag(), "Tailscale candidate directory identities overlap")
			}
		}
		for _, old := range runtimeTailscaleParticipants(retained) {
			overlap, err := runtimeTailscaleOptionsOverlap(s.runtime.ctx, value.RuntimePhysicalOptions(), old.RuntimePhysicalOptions())
			if err != nil {
				return t, err
			}
			if !overlap {
				continue
			}
			if selected[value] != nil && selected[value].NATIdentity() != nil && selected[value].NATIdentity() == old.NATIdentity() {
				continue
			}
			return t, runtimeEndpointRestart(value.Tag(), "Tailscale state or Taildrop directory is still owned by an incompatible physical identity")
		}
	}
	for _, value := range t.next {
		if err := ctx.Err(); err != nil {
			return t, err
		}
		if selected[value] != nil {
			continue
		}
		// Graph-facing policies are supplied by concrete per-generation hooks. The
		// physical base retains only the existing stable platform/network lifetime.
		base := service.ExtendContext(s.runtime.ctx)
		service.MustRegister[adapter.NetworkManager](base, s.network)
		if err := value.RuntimeSetPhysicalBase(base, s.runtime.stable.owner, s.logFactory.NewLogger("endpoint/tailscale["+value.Tag()+"]")); err != nil {
			return t, err
		}
		t.reserved = append(t.reserved, value)
		if err := value.RuntimeReservePhysical(ctx); err != nil {
			return t, err
		}
	}
	for _, value := range t.next {
		if err := ctx.Err(); err != nil {
			return t, err
		}
		if old := selected[value]; old != nil {
			if err := value.RuntimeStageSharedPhysical(ctx, old); err != nil {
				return t, err
			}
		} else if err := value.RuntimeStagePhysical(ctx); err != nil {
			return t, err
		}
	}
	return t, nil
}

func (t *runtimeTailscaleEndpointTransaction) preparePublication() error {
	if t == nil {
		return nil
	}
	var err error
	t.publication, err = protocolTS.PrepareRuntimeEndpointPublication(t.next)
	return err
}

func (t *runtimeTailscaleEndpointTransaction) publish() {
	if t != nil {
		t.publication.Publish()
	}
}

func (t *runtimeTailscaleEndpointTransaction) compensate(ctx context.Context) error {
	if t == nil {
		return nil
	}
	var err error
	for _, value := range slices.Backward(t.next) {
		err = errors.Join(err, value.RuntimeCloseAndWait())
	}
	for _, value := range slices.Backward(t.reserved) {
		err = errors.Join(err, value.RuntimeReleasePhysicalReservation(ctx))
	}
	return err
}

// This pure normalized-path check never acquires directory custody. The existing
// native directory plan remains authoritative for aliases and OS file identity.
func runtimeTailscaleDirectoriesOverlap(a, b string) bool {
	relative, err := filepath.Rel(a, b)
	if err == nil && (relative == "." || relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return true
	}
	relative, err = filepath.Rel(b, a)
	return err == nil && (relative == "." || relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func runtimeTailscaleOptionsOverlap(ctx context.Context, a, b option.TailscaleEndpointOptions) (bool, error) {
	as, at, err := protocolTS.RuntimePhysicalDirectories(ctx, a)
	if err != nil {
		return false, err
	}
	bs, bt, err := protocolTS.RuntimePhysicalDirectories(ctx, b)
	if err != nil {
		return false, err
	}
	for _, left := range []string{as, at} {
		for _, right := range []string{bs, bt} {
			if runtimeTailscaleDirectoriesOverlap(left, right) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *Box) preflightRuntimeTailscaleEndpoints(ctx context.Context, options option.Options, intents []RuntimeSelectorIntent, rootDigest [32]byte) error {
	type input struct {
		tag     string
		options option.TailscaleEndpointOptions
	}
	var inputs []input
	for index, endpoint := range options.Endpoints {
		if endpoint.Type != C.TypeTailscale {
			continue
		}
		value, ok := endpoint.Options.(*option.TailscaleEndpointOptions)
		if !ok {
			return errors.New("invalid Tailscale endpoint options")
		}
		tag := endpoint.Tag
		if tag == "" {
			tag = fmt.Sprint(index)
		}
		inputs = append(inputs, input{tag, *value})
	}
	if len(inputs) == 0 {
		return nil
	}
	c := s.runtime
	c.access.Lock()
	c.pruneRuntimeCatalogLocked()
	current := append([]*runtimeResource(nil), c.resources...)
	var retained []*runtimeResource
	for _, resource := range c.catalog {
		if resource.networkReady {
			retained = append(retained, resource)
		}
	}
	c.access.Unlock()
	replaced, err := runtimeReplacementNames(ctx, options, intents, rootDigest, current)
	if err != nil {
		return err
	}
	kept := make(map[string]bool)
	for _, value := range inputs {
		if !replaced["endpoint:"+value.tag] {
			kept[value.tag] = true
		}
	}
	for index, value := range inputs {
		if !replaced["endpoint:"+value.tag] {
			continue
		}
		// No candidate may publish two logical bindings for one directory identity.
		for otherIndex, other := range inputs {
			if otherIndex == index {
				continue
			}
			overlap, err := runtimeTailscaleOptionsOverlap(c.ctx, value.options, other.options)
			if err != nil {
				return err
			}
			if overlap {
				return runtimeEndpointRestart(value.tag, "Tailscale candidate directory identities overlap")
			}
		}
		var match *protocolTS.Endpoint
		for _, old := range runtimeTailscaleParticipants(current) {
			if !old.RuntimeCanSharePhysical(value.tag, value.options) {
				continue
			}
			if kept[old.Tag()] {
				return runtimeEndpointRestart(value.tag, "Tailscale physical identity cannot have two active logical endpoints")
			}
			if match != nil && match.NATIdentity() != old.NATIdentity() {
				return runtimeEndpointRestart(value.tag, "Tailscale physical identity has ambiguous prior ownership")
			}
			match = old
		}
		for _, old := range runtimeTailscaleParticipants(retained) {
			overlap, err := runtimeTailscaleOptionsOverlap(c.ctx, value.options, old.RuntimePhysicalOptions())
			if err != nil {
				return err
			}
			if !overlap {
				continue
			}
			if match != nil && match.NATIdentity() != nil && match.NATIdentity() == old.NATIdentity() {
				continue
			}
			return runtimeEndpointRestart(value.tag, "Tailscale state or Taildrop directory is still owned by an incompatible physical identity")
		}
	}
	return nil
}
