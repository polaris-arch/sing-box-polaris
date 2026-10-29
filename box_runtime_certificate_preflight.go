package box

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service/filemanager"
)

// Claims live on the allocation until its real cleanup completes, including
// retired graphs and uncertain cleanup. They are not tag-based global lookups.
// Opaque default storage conflicts with every storage owner: its concrete
// process-wide implementation is not necessarily a filesystem directory.
type runtimeCertificateClaim struct {
	component string
	path      string
	directory string
	object    os.FileInfo
	ancestors []os.FileInfo
	opaque    bool
	listener  bool
	ports     []uint16
	domains   []string
}

func runtimeCertificateDirectory(ctx context.Context, directory string) (string, error) {
	path, err := filepath.Abs(filemanager.BasePath(ctx, os.ExpandEnv(directory)))
	if err != nil {
		return "", err
	}
	// Resolve the existing prefix without creating candidate directories. This
	// catches aliases even when the leaf will only be created during staging.
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			for _, part := range slices.Backward(missing) {
				resolved = filepath.Join(resolved, part)
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", err
		}
		missing = append(missing, filepath.Base(path))
		path = parent
	}
}

func runtimeCertificateClaims(ctx context.Context, options option.Options) ([]runtimeCertificateClaim, error) {
	var claims []runtimeCertificateClaim
	add := func(component, path string, value any) error {
		claim := runtimeCertificateClaim{component: component, path: path}
		var directory string
		switch v := value.(type) {
		case *option.ACMECertificateProviderOptions:
			if v == nil {
				return errors.New("missing certificate options")
			}
			directory = v.DataDirectory
			if v.DNS01Challenge == nil {
				if !v.DisableHTTPChallenge {
					port := v.AlternativeHTTPPort
					if port == 0 {
						port = 80
					}
					claim.ports = append(claim.ports, port)
				}
				if !v.DisableTLSALPNChallenge {
					port := v.AlternativeTLSPort
					if port == 0 {
						port = 443
					}
					claim.ports = append(claim.ports, port)
				}
			} else {
				for _, domain := range v.Domain {
					claim.domains = append(claim.domains, strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*."), "."))
				}
				// An explicit override is the actual shared challenge identity.
				if override := v.DNS01Challenge.OverrideDomain; override != "" {
					claim.domains = []string{strings.TrimSuffix(strings.ToLower(override), ".")}
				}
			}
		case *option.CloudflareOriginCACertificateProviderOptions:
			if v == nil {
				return errors.New("missing certificate options")
			}
			directory = v.DataDirectory
		default:
			return nil // Tailscale's exact endpoint owns its directory and listener.
		}
		claim.opaque = directory == ""
		if !claim.opaque {
			var err error
			claim.directory, err = runtimeCertificateDirectory(ctx, directory)
			if err != nil {
				return err
			}
			for ancestor := claim.directory; ; ancestor = filepath.Dir(ancestor) {
				if info, err := certificate.RuntimeDirectoryIdentity(ancestor); err == nil {
					if ancestor == claim.directory {
						claim.object = info
					}
					claim.ancestors = append(claim.ancestors, info)
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
				if filepath.Dir(ancestor) == ancestor {
					break
				}
			}
		}
		claims = append(claims, claim)
		return nil
	}
	for i, provider := range options.CertificateProviders {
		tag := provider.Tag
		if tag == "" {
			tag = fmt.Sprint(i)
		}
		if err := add("certificate-provider:"+tag, fmt.Sprintf("certificate_providers[%d]", i), provider.Options); err != nil {
			return nil, err
		}
	}
	for i, inbound := range options.Inbounds {
		tag := inbound.Tag
		if tag == "" {
			tag = fmt.Sprint(i)
		}
		if wrapper, ok := inbound.Options.(option.ListenOptionsWrapper); ok && wrapper.TakeListenOptions().ListenPort != 0 {
			claims = append(claims, runtimeCertificateClaim{component: "inbound:" + tag, path: fmt.Sprintf("inbounds[%d]", i), listener: true, ports: []uint16{wrapper.TakeListenOptions().ListenPort}})
		}
		wrapper, ok := inbound.Options.(option.InboundTLSOptionsWrapper)
		if !ok {
			continue
		}
		tls := wrapper.TakeInboundTLSOptions()
		if tls == nil || !tls.Enabled || tls.CertificateProvider == nil || tls.CertificateProvider.Tag != "" {
			continue
		}
		if err := add("inbound:"+tag, fmt.Sprintf("inbounds[%d].tls.certificate_provider", i), tls.CertificateProvider.Options); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

func runtimeCertificateClaimsOverlap(a, b runtimeCertificateClaim) bool {
	if a.listener && b.listener {
		return false
	}
	if !a.listener && !b.listener && (a.opaque || b.opaque) {
		return true
	}
	within := func(root, path string) bool {
		rel, err := filepath.Rel(root, path)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	if !a.listener && !b.listener && (within(a.directory, b.directory) || within(b.directory, a.directory)) {
		return true
	}
	// Compare retained object identities as well as names. A renamed directory
	// (or a bind alias) remains owned even after its original path disappears.
	if !a.listener && !b.listener {
		if a.object != nil {
			for _, parent := range b.ancestors {
				if os.SameFile(a.object, parent) {
					return true
				}
			}
		}
		if b.object != nil {
			for _, parent := range a.ancestors {
				if os.SameFile(b.object, parent) {
					return true
				}
			}
		}
	}
	for _, x := range a.ports {
		if slices.Contains(b.ports, x) {
			return true
		}
	}
	for _, x := range a.domains {
		if slices.Contains(b.domains, x) {
			return true
		}
	}
	return false
}

func runtimeCertificateClaimProblems(claims []runtimeCertificateClaim, replaced map[string]bool, live []*runtimeResource) []RuntimePlanError {
	bad := make(map[string]bool)
	for i, claim := range claims {
		for _, other := range claims[:i] {
			if runtimeCertificateClaimsOverlap(claim, other) {
				bad[claim.path] = true
			}
		}
		if !replaced[claim.component] {
			continue
		}
		for _, resource := range live {
			for _, other := range resource.certificateClaims {
				if runtimeCertificateClaimsOverlap(claim, other) {
					bad[claim.path] = true
				}
			}
		}
	}
	var paths []string
	for path := range bad {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var problems []RuntimePlanError
	for _, path := range paths {
		problems = append(problems, RuntimePlanError{Code: "RESTART_REQUIRED", Path: path, Message: "certificate cache, challenge listener or DNS challenge identity overlaps a retained owner; explicit host-managed restart required"})
	}
	return problems
}

func (s *Box) preflightRuntimeCertificates(ctx context.Context, options option.Options, intents []RuntimeSelectorIntent, root [32]byte) ([]RuntimePlanError, error) {
	claims, err := runtimeCertificateClaims(ctx, options)
	if err != nil {
		return nil, err
	}
	s.runtime.access.Lock()
	s.runtime.pruneRuntimeCatalogLocked()
	current := append([]*runtimeResource(nil), s.runtime.resources...)
	live := s.runtime.runtimeCertificateLiveLocked()
	s.runtime.access.Unlock()
	replaced, err := runtimeReplacementNames(ctx, options, intents, root, current)
	if err != nil {
		return nil, err
	}
	return runtimeCertificateClaimProblems(claims, replaced, live), nil
}

// Recheck and reserve before provider construction/staging. Publication does not
// release these claims; terminal owner cleanup is the only release authority.
func (s *Box) reserveRuntimeCertificateClaims(g *preparedRuntimeGraph, bindings map[string]*runtimeResource, owned map[*runtimeResource]bool) error {
	claims, err := runtimeCertificateClaims(s.runtime.ctx, g.options)
	if err != nil {
		return err
	}
	replaced := make(map[string]bool)
	for name, resource := range bindings {
		replaced[name] = owned[resource]
	}
	s.runtime.access.Lock()
	live := s.runtime.runtimeCertificateLiveLocked()
	s.runtime.access.Unlock()
	if problems := runtimeCertificateClaimProblems(claims, replaced, live); len(problems) != 0 {
		return &runtimeEndpointRestartRequiredError{detail: problems[0]}
	}
	g.certificateClaimContext, g.certificateClaims = s.runtime.ctx, claims
	g.checkCertificateClaims = func(fresh []runtimeCertificateClaim) error {
		// Charge every observed identity BEFORE conflict/drift rejection. Failed
		// stages and Unknown cleanup retain the union, never the last snapshot.
		s.runtime.access.Lock()
		defer s.runtime.access.Unlock()
		for _, claim := range fresh {
			if resource := bindings[claim.component]; resource != nil && owned[resource] {
				resource.certificateClaims = runtimeCertificateClaimUnion(resource.certificateClaims, claim)
			}
		}
		var retained []*runtimeResource
		for _, resource := range s.runtime.catalog {
			if !owned[resource] {
				retained = append(retained, &runtimeResource{certificateClaims: append([]runtimeCertificateClaim(nil), resource.certificateClaims...)})
			}
		}
		if problems := runtimeCertificateClaimProblems(fresh, replaced, retained); len(problems) != 0 {
			return &runtimeEndpointRestartRequiredError{detail: problems[0]}
		}
		return nil
	}
	g.bindCertificateStorage = func(component string, identity os.FileInfo) error {
		var actual []runtimeCertificateClaim
		for _, claim := range g.certificateClaims {
			if claim.component == component && !claim.listener {
				bound := claim
				bound.object, bound.ancestors = identity, []os.FileInfo{identity}
				if identity == nil {
					bound.opaque = true
				}
				actual = append(actual, bound)
			}
		}
		if len(actual) == 0 {
			return errors.New("certificate storage has no reserved owner")
		}
		boundErr := g.checkCertificateClaims(actual)
		// Also reserve aliases observed while OpenRoot raced with configuration
		// paths, even when actual storage cannot pass the original identity check.
		freshErr := g.validateRuntimeCertificateClaims()
		if identity == nil {
			return errors.Join(boundErr, freshErr, errors.New("certificate storage directory identity is unconfirmed"))
		}
		for _, claim := range g.certificateClaims {
			if claim.component == component && !claim.listener && claim.object != nil && !os.SameFile(claim.object, identity) {
				return errors.Join(boundErr, freshErr, errors.New("certificate storage opened a different directory identity"))
			}
		}
		return errors.Join(boundErr, freshErr)
	}

	s.runtime.access.Lock()
	defer s.runtime.access.Unlock()
	for _, claim := range claims {
		resource := bindings[claim.component]
		if resource != nil && owned[resource] {
			resource.certificateClaims = append(resource.certificateClaims, claim)
		}
	}
	return nil
}

// Snapshot claim slices while guarded; preparing owners publish them once and
// Plan may run concurrently. Filesystem identity probes run after unlocking.
func (c *runtimeCoordinator) runtimeCertificateLiveLocked() []*runtimeResource {
	var live []*runtimeResource
	for _, resource := range c.catalog {
		live = append(live, &runtimeResource{certificateClaims: append([]runtimeCertificateClaim(nil), resource.certificateClaims...)})
	}
	return live
}

func runtimeCertificateClaimIdentitiesEqual(previous, current []runtimeCertificateClaim) bool {
	if len(previous) != len(current) {
		return false
	}
	for i, before := range previous {
		after := current[i]
		if before.object != nil && (after.object == nil || !os.SameFile(before.object, after.object)) {
			return false
		}
		if before.object == nil {
			// Staging may create the missing leaf, but cannot silently replace an
			// existing ancestor captured by preflight. New directories prepend
			// identities; the previously existing suffix must remain the same.
			if len(after.ancestors) < len(before.ancestors) {
				return false
			}
			for j, parent := range before.ancestors {
				if !os.SameFile(parent, after.ancestors[len(after.ancestors)-len(before.ancestors)+j]) {
					return false
				}
			}
		}
		before.object, before.ancestors, after.object, after.ancestors = nil, nil, nil, nil
		if !reflect.DeepEqual(before, after) {
			return false
		}
	}
	return true
}

func runtimeCertificateClaimUnion(previous []runtimeCertificateClaim, claim runtimeCertificateClaim) []runtimeCertificateClaim {
	for _, before := range previous {
		if runtimeCertificateClaimIdentitiesEqual([]runtimeCertificateClaim{before}, []runtimeCertificateClaim{claim}) &&
			((before.object == nil) == (claim.object == nil)) {
			return previous
		}
	}
	return append(previous, claim)
}

func (g *preparedRuntimeGraph) validateRuntimeCertificateClaims() error {
	if g.certificateClaimContext == nil {
		return nil
	}
	claims, probeErr := runtimeCertificateClaims(g.certificateClaimContext, g.options)
	if probeErr != nil {
		// A failed path probe cannot prove where a partial effect went. Retain
		// historical identities and an opaque exclusion until real cleanup.
		for _, old := range g.certificateClaims {
			if !old.listener {
				old.opaque = true
				claims = append(claims, old)
			}
		}
	}
	var claimErr error
	if g.checkCertificateClaims != nil {
		claimErr = g.checkCertificateClaims(claims)
	}
	if probeErr != nil || !runtimeCertificateClaimIdentitiesEqual(g.certificateClaims, claims) {
		return errors.Join(probeErr, claimErr, errors.New("certificate resource identity changed during preparation"))
	}
	if claimErr != nil {
		return claimErr
	}
	g.certificateClaims = claims
	return nil
}
