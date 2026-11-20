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

type runtimeTailscaleInput struct {
	tag     string
	options option.TailscaleEndpointOptions
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

// Rebuilding a logical cohort can keep its original physical writer. Native
// writers also require the original tag and exactly one current owner.
func matchRuntimeTailscaleWriters(inputs []runtimeTailscaleInput, prior []*protocolTS.Endpoint, kept map[*protocolTS.Endpoint]bool, native bool) (map[string]*protocolTS.Endpoint, error) {
	matches := make(map[string]*protocolTS.Endpoint)
	shared := make(map[*protocolTS.Endpoint]bool)
	matched := make(map[*protocolTS.Endpoint]bool)
	for _, input := range inputs {
		var physical *protocolTS.Endpoint
		var match *protocolTS.Endpoint
		for _, old := range prior {
			if !old.RuntimeCanSharePhysical(input.tag, input.options) {
				continue
			}
			if kept[old] {
				return nil, runtimeEndpointRestart(input.tag, "Tailscale physical identity cannot have two active logical endpoints")
			}
			if native && old.Tag() != input.tag {
				continue
			}
			owner, _ := old.NATIdentity().(*protocolTS.Endpoint)
			if owner == nil || match != nil && (native || physical != owner) {
				return nil, runtimeEndpointRestart(input.tag, "Tailscale physical identity has ambiguous prior ownership")
			}
			physical = owner
			match = old
		}
		if physical != nil {
			if shared[physical] {
				return nil, runtimeEndpointRestart(input.tag, "Tailscale candidate duplicates a shared physical identity")
			}
			shared[physical] = true
			matched[match] = true
			matches[input.tag] = match
		}
	}
	if native {
		for _, old := range prior {
			if !kept[old] && !matched[old] {
				return nil, runtimeEndpointRestart(old.Tag(), "Android warm Tailscale requires retaining existing endpoint writers")
			}
		}
	}
	return matches, nil
}

func validateRuntimeTailscaleAdditions(ctx context.Context, platform adapter.RuntimeTailscaleWriterPlatform, inputs []runtimeTailscaleInput, matches map[string]*protocolTS.Endpoint) (bool, error) {
	var first runtimeTailscaleInput
	additions := 0
	for _, input := range inputs {
		if matches[input.tag] == nil {
			if additions == 0 {
				first = input
			}
			additions++
		}
	}
	if additions == 0 {
		return false, nil
	}
	return true, validateRuntimeTailscaleWriter(ctx, platform, additions, first.tag, first.options)
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
	inputs := make([]runtimeTailscaleInput, 0, len(t.next))
	for _, value := range t.next {
		if err := value.RuntimeValidate(); err != nil {
			return t, err
		}
		inputs = append(inputs, runtimeTailscaleInput{value.Tag(), value.RuntimePhysicalOptions()})
	}
	platform := adapter.RuntimeTailscaleWriterFromContext(s.runtime.ctx)
	native := !g.initial && platform != nil
	selected, err := matchRuntimeTailscaleWriters(inputs, prior, kept, native)
	if err != nil {
		return t, err
	}
	if native {
		addition, err := validateRuntimeTailscaleAdditions(s.runtime.ctx, platform, inputs, selected)
		if err != nil {
			return t, err
		}
		if addition {
			ctx = adapter.ContextWithRuntimeTailscaleNativeWriter(ctx)
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
			if match := selected[value.Tag()]; match != nil && match.NATIdentity() != nil && match.NATIdentity() == old.NATIdentity() {
				continue
			}
			return t, runtimeEndpointRestart(value.Tag(), "Tailscale state or Taildrop directory is still owned by an incompatible physical identity")
		}
	}
	for _, value := range t.next {
		if err := ctx.Err(); err != nil {
			return t, err
		}
		if selected[value.Tag()] != nil {
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
		if old := selected[value.Tag()]; old != nil {
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
	var inputs []runtimeTailscaleInput
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
		inputs = append(inputs, runtimeTailscaleInput{tag, *value})
	}
	c := s.runtime
	platform := adapter.RuntimeTailscaleWriterFromContext(c.ctx)
	if len(inputs) == 0 {
		if platform != nil {
			c.access.Lock()
			defer c.access.Unlock()
			for _, old := range runtimeTailscaleParticipants(c.resources) {
				return runtimeEndpointRestart(old.Tag(), "Android warm Tailscale requires retaining existing endpoint writers")
			}
		}
		return nil
	}
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
	prior := runtimeTailscaleParticipants(current)
	kept := make(map[*protocolTS.Endpoint]bool)
	var changed []runtimeTailscaleInput
	for _, value := range inputs {
		if replaced["endpoint:"+value.tag] {
			changed = append(changed, value)
			continue
		}
		for _, old := range prior {
			if old.Tag() == value.tag {
				kept[old] = true
			}
		}
	}
	selected, err := matchRuntimeTailscaleWriters(changed, prior, kept, platform != nil)
	if err != nil {
		return err
	}
	if platform != nil {
		if _, err := validateRuntimeTailscaleAdditions(c.ctx, platform, changed, selected); err != nil {
			return err
		}
	}
	for index, value := range inputs {
		if !replaced["endpoint:"+value.tag] {
			continue
		}
		match := selected[value.tag]
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

func validateRuntimeTailscaleWriter(ctx context.Context, platform adapter.RuntimeTailscaleWriterPlatform, additions int, tag string, options option.TailscaleEndpointOptions) error {
	if additions != 1 || options.SystemInterface || options.StateDirectory == "" || options.SSHServer != nil && options.SSHServer.Enabled {
		return runtimeEndpointRestart(tag, "Android warm Tailscale requires one new scoped userspace endpoint with an explicit state directory")
	}
	state, taildrop, err := protocolTS.RuntimePhysicalDirectories(ctx, options)
	if err != nil {
		return err
	}
	if !adapter.RuntimeTailscaleChildHasCapacity(ctx) ||
		!platform.ValidateRuntimeTailscaleWriter(tag, adapter.RuntimeTailscaleDirectories{State: state, Taildrop: taildrop}) {
		return runtimeEndpointRestart(tag, "Android warm Tailscale writer admission is unavailable")
	}
	return nil
}
