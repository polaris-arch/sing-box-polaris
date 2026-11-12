package box

import (
	"context"
	"errors"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	protocolTun "github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing/service"
)

func (s *Box) prepareRuntimeFakeIP(ctx context.Context, prepared *preparedRuntimeGraph) error {
	if s.runtime.fakeIP == nil {
		return errors.New("runtime fake-IP authority unavailable")
	}
	var configuration *option.FakeIPDNSServerOptions
	var servers []option.DNSServerOptions
	if prepared.options.DNS != nil {
		servers = prepared.options.DNS.Servers
	}
	for _, server := range servers {
		if server.Type != C.DNSTypeFakeIP {
			continue
		}
		if configuration != nil {
			return errors.New("multiple fakeip servers are not supported")
		}
		var ok bool
		configuration, ok = server.Options.(*option.FakeIPDNSServerOptions)
		if !ok || configuration == nil {
			return errors.New("invalid fake-IP server options")
		}
	}
	// Private source-only publication cannot create a namespace.
	// Select this before any allocation path.
	if runtimeSourceOnlyContext(ctx) {
		var migration *fakeip.RangeMigration
		var err error
		if configuration == nil {
			migration, err = s.runtime.fakeIP.PrepareUnchangedSelection(ctx)
		} else {
			migration, err = s.runtime.fakeIP.PrepareUnchangedRanges(ctx, configuration.Inet4Range.Build(netip.Prefix{}), configuration.Inet6Range.Build(netip.Prefix{}))
		}
		if err != nil {
			return err
		}
		prepared.fakeIPMigration = migration
		return nil
	}
	// Removal stops new answers through the graph while retaining recognition
	// and the exact allocator for old flows and answers within their validity.
	if configuration == nil {
		return nil
	}
	var migration *fakeip.RangeMigration
	var err error
	cache := service.FromContext[adapter.CacheFile](s.runtime.ctx)
	if prepared.initial && cache != nil && cache.StoreFakeIP() {
		migration, err = s.runtime.fakeIP.PrepareInitialPersistentRanges(ctx, configuration.Inet4Range.Build(netip.Prefix{}), configuration.Inet6Range.Build(netip.Prefix{}), cache)
	} else {
		migration, err = s.runtime.fakeIP.PrepareRanges(ctx, configuration.Inet4Range.Build(netip.Prefix{}), configuration.Inet6Range.Build(netip.Prefix{}))
		if errors.Is(err, fakeip.ErrInitialPersistentBindingRequired) && cache != nil && cache.StoreFakeIP() {
			migration, err = s.runtime.fakeIP.PrepareInitialPersistentRanges(ctx, configuration.Inet4Range.Build(netip.Prefix{}), configuration.Inet6Range.Build(netip.Prefix{}), cache)
		}
	}
	if err != nil {
		return err
	}
	prepared.fakeIPMigration = migration
	return nil
}

func (g *preparedRuntimeGraph) fenceRuntimeFakeIP(contexts ...context.Context) (*fakeip.RangeCommit, error) {
	if g.fakeIPMigration == nil {
		return nil, nil
	}
	if len(contexts) > 0 && runtimeSourceOnlyContext(contexts[0]) && !g.fakeIPMigration.UnchangedSelection() {
		return nil, errors.New("source-only fake-IP selection changed")
	}
	commit, _, err := g.fakeIPMigration.PrepareCommit()
	return commit, err
}

// A nil typed commit must never be boxed as a nonnil publication participant.
type runtimeFakeIPPublication struct {
	logPublication func()
	log            *log.RuntimeLogPublication
	apiHandoffs    []adapter.RuntimeAPIHandoff
	endpoints      *runtimeEndpointTransaction
	dnsStores      []*cachefile.DNSRuntimeView
	tun            *protocolTun.RuntimeTunPublication
	commit         *fakeip.RangeCommit
	listeners      *listener.PreparedListenerPublication
}

func (p runtimeFakeIPPublication) abort() {
	if p.log != nil {
		p.log.Finish()
	}
	if p.listeners != nil {
		p.listeners.Finish()
	}
	if p.commit != nil {
		p.commit.Abort()
	}
}

func (p runtimeFakeIPPublication) Publish() {
	if p.log != nil {
		p.log.Publish()
	}
	for _, handoff := range p.apiHandoffs {
		if publisher, ok := handoff.(interface{ PublishRuntimeAPI() }); ok {
			publisher.PublishRuntimeAPI()
		}
	}
	if p.logPublication != nil {
		p.logPublication()
	}
	if p.endpoints != nil {
		p.endpoints.Publish()
	}
	for _, stores := range p.dnsStores {
		stores.Activate()
	}
	if p.commit != nil {
		p.commit.Publish()
	}
	if p.listeners != nil {
		p.listeners.Publish()
	}
	if p.tun != nil {
		p.tun.Publish()
	}
}

func (p runtimeFakeIPPublication) publish(store *runtimegraph.Store, expected adapter.RuntimeRevision, graph *runtimegraph.Graph) (*runtimegraph.Graph, error) {
	if p.logPublication == nil && p.log == nil && len(p.apiHandoffs) == 0 && p.endpoints == nil && p.commit == nil && p.listeners == nil && p.tun == nil && len(p.dnsStores) == 0 {
		return store.Publish(expected, graph)
	}
	return store.PublishPrepared(expected, graph, p)
}

func runtimeFakeIPRangeProblems(manager *fakeip.Manager, options option.Options) []RuntimePlanError {
	if manager == nil || options.DNS == nil {
		return nil
	}
	before4, before6, initialized := manager.RuntimeRangeIdentity()
	if !initialized {
		return nil
	}
	for _, server := range options.DNS.Servers {
		if server.Type != C.DNSTypeFakeIP {
			continue
		}
		value, ok := server.Options.(*option.FakeIPDNSServerOptions)
		if !ok || value == nil {
			return []RuntimePlanError{{Code: "INVALID_CONFIG", Path: "dns.servers", Message: "invalid fake-IP configuration"}}
		}
		if value.Inet4Range.Build(netip.Prefix{}).Masked() != before4 || value.Inet6Range.Build(netip.Prefix{}).Masked() != before6 {
			return []RuntimePlanError{{Code: "RESTART_REQUIRED", Path: "dns.servers", DependencyPath: []string{"fakeip.retained_range_identity"}, Message: "changing retained fake-IP ranges requires a separate namespace migration decision"}}
		}
	}
	return nil
}

// The central stable-owner callback calls this before closing its child scopes.
func (c *runtimeCoordinator) closeRuntimeFakeIP() error {
	if c.fakeIP != nil {
		return c.fakeIP.Close()
	}
	return nil
}

func (s *Box) runtimeClientFakeIPRangeProblems(options option.Options, policy uint32) []RuntimePlanError {
	problems := runtimeFakeIPRangeProblems(s.runtime.fakeIP, options)
	if len(problems) == 0 || policy != 1 {
		return problems
	}
	before4, before6, _ := s.runtime.fakeIP.RuntimeRangeIdentity()
	fixed4, fixed6 := netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("2001:2::/48")
	if before4 != fixed4 || (before6.IsValid() && before6 != fixed6) {
		return problems
	}
	count := 0
	if options.DNS != nil {
		for _, server := range options.DNS.Servers {
			if server.Type != C.DNSTypeFakeIP {
				continue
			}
			count++
			value, ok := server.Options.(*option.FakeIPDNSServerOptions)
			if !ok || value == nil || value.Inet4Range.Build(netip.Prefix{}).Masked() != fixed4 {
				return problems
			}
			after6 := value.Inet6Range.Build(netip.Prefix{}).Masked()
			if after6.IsValid() && after6 != fixed6 {
				return problems
			}
		}
	}
	if count != 1 {
		return problems
	}
	s.runtime.access.Lock()
	persistBound := s.runtime.persist != nil
	s.runtime.access.Unlock()
	if !persistBound {
		return []RuntimePlanError{{Code: "RESTART_REQUIRED", Path: "dns.servers", DependencyPath: []string{"fakeip.configuration_durability"}, Message: "range migration requires the original configuration persistence owner"}}
	}
	// A store_fakeip allocator keeps its cache.db mappings; ranges change on restart.
	cache := service.FromContext[adapter.CacheFile](s.runtime.ctx)
	if cache != nil && cache.StoreFakeIP() {
		return []RuntimePlanError{{Code: "RESTART_REQUIRED", Path: "dns.servers", DependencyPath: []string{"fakeip.store_fakeip"}, Message: "persistent store_fakeip ranges change only on restart"}}
	}
	return nil
}
