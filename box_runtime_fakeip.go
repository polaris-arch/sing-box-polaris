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
	"github.com/sagernet/sing-box/option"
	protocolTun "github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing/service"
)

func (s *Box) prepareRuntimeFakeIP(ctx context.Context, prepared *preparedRuntimeGraph) error {
	if prepared.options.DNS == nil {
		return nil
	}
	var configuration *option.FakeIPDNSServerOptions
	for _, server := range prepared.options.DNS.Servers {
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
	// Removal stops new answers through the graph while retaining recognition
	// and the exact allocator for old flows and answers within their validity.
	if configuration == nil {
		return nil
	}
	if s.runtime.fakeIP == nil {
		return errors.New("runtime fake-IP authority unavailable")
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

func (g *preparedRuntimeGraph) fenceRuntimeFakeIP() (*fakeip.RangeCommit, error) {
	if g.fakeIPMigration == nil {
		return nil, nil
	}
	commit, _, err := g.fakeIPMigration.PrepareCommit()
	return commit, err
}

// A nil typed commit must never be boxed as a nonnil publication participant.
type runtimeFakeIPPublication struct {
	logPublication func()
	endpoints      *runtimeEndpointTransaction
	dnsStores      []*cachefile.DNSRuntimeView
	tun            *protocolTun.RuntimeTunPublication
	commit         *fakeip.RangeCommit
	listeners      *listener.PreparedListenerPublication
}

func (p runtimeFakeIPPublication) abort() {
	if p.listeners != nil {
		p.listeners.Finish()
	}
	if p.commit != nil {
		p.commit.Abort()
	}
}

func (p runtimeFakeIPPublication) Publish() {
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
	if p.endpoints == nil && p.commit == nil && p.listeners == nil && p.tun == nil && len(p.dnsStores) == 0 {
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
