package box

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	roots "github.com/sagernet/sing-box/common/certificate"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/runtimeclock"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/option"
	protocolTun "github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-tun"
)

// runtimeView is immutable once passed to NewGraph. Resource maps are never
// caller-owned and contain the complete admitted transitive closure.
type runtimeView struct {
	histories          map[string]*urltest.HistoryStorage
	historyConsumers   map[string][]*urltest.HistoryStorage
	referenceOptions   *route.RuntimeReferenceOptions
	referenceResources map[any]adapter.RuntimeResourceID
	identity           adapter.RuntimeRevision
	router             adapter.Router
	dns                adapter.DNSRouter
	inbounds           adapter.InboundManager
	outbounds          adapter.OutboundManager
	endpoints          adapter.EndpointManager
	transports         adapter.DNSTransportManager
	httpClients        *httpclient.Manager
	dashboardHTTP      map[runtimeDashboardHTTPKey]adapter.HTTPTransport
	network            adapter.NetworkManager
	ports              map[tun.Port]adapter.RuntimeResourceID
	componentIDs       map[string]adapter.RuntimeResourceID
}

func (v *runtimeView) Identity() adapter.RuntimeRevision                { return v.identity }
func (v *runtimeView) Router() adapter.Router                           { return v.router }
func (v *runtimeView) DNSRouter() adapter.DNSRouter                     { return v.dns }
func (v *runtimeView) InboundManager() adapter.InboundManager           { return v.inbounds }
func (v *runtimeView) OutboundManager() adapter.OutboundManager         { return v.outbounds }
func (v *runtimeView) EndpointManager() adapter.EndpointManager         { return v.endpoints }
func (v *runtimeView) DNSTransportManager() adapter.DNSTransportManager { return v.transports }
func (v *runtimeView) NetworkManager() adapter.NetworkManager           { return v.network }
func (v *runtimeView) RuntimePortResource(port tun.Port) (adapter.RuntimeResourceID, bool) {
	id, ok := v.ports[port]
	return id, ok
}

type runtimeResource struct {
	postBindEffects []runtimePostBindRecord
	sourceProducer  *runtimeSourceProducer
	rootStore       *roots.Store
	id              adapter.RuntimeResourceID
	kind            string
	fingerprint     string
	owner           *runtimegraph.ResourceOwner
	scope           *adapter.Scope
	networkReady    bool // guarded by coordinator.access; components immutable once true
	components      map[string]*runtimeComponent
	// stop seals producer roots, without canceling existing foreground work.
	stop      func()
	stopFinal func()
}

type runtimeComponent struct {
	service       adapter.Service
	clock         *runtimeclock.Service
	endpoint      adapter.Endpoint
	provider      adapter.CertificateProviderService
	httpClients   *httpclient.Manager
	dashboardHTTP map[runtimeDashboardHTTPKey]adapter.HTTPTransport
	history       *urltest.HistoryStorage
	inbound       adapter.Inbound
	outbound      adapter.Outbound
	transport     adapter.DNSTransport
	ruleSet       adapter.RuleSet
	router        *route.Router
	dns           *dns.Router
}

type preparedRuntimeGraph struct {
	dnsStores                []*cachefile.DNSRuntimeView
	published                bool // written at commit; cleanup reads after the preparing operation joins
	postBindNext             []runtimePostBindRecord
	postBindPrevious         []runtimePostBindRecord
	postBindStaged           []runtimePostBindRecord
	postBindSuspended        []runtimePostBindRecord
	postBindError            error
	rootResource             *runtimeResource
	rootSnapshot             *roots.RootSnapshot
	rootDigest               [32]byte
	logPublication           func()
	endpointTransaction      *runtimeEndpointTransaction
	tunTransaction           *protocolTun.RuntimeSetTransaction
	tunRestorationError      error
	certificateManager       *certificate.Manager
	stagedProviders          []adapter.RuntimeStagedEffect
	effectAccess             sync.Mutex
	effectRegistrationClosed bool
	inlineEffects            []adapter.RuntimeStagedEffect
	externalEffectsAttempted bool
	compensationError        error
	serviceManager           *boxService.Manager
	endpointManager          *endpoint.Manager
	inboundManager           *inbound.Manager
	listenerTransaction      *listener.ListenerSetTransaction
	listenerRestoration      *listener.Restoration
	fakeIPMigration          *fakeip.RangeMigration
	graph                    *runtimegraph.Graph
	view                     *runtimeView
	resources                []*runtimeResource
	created                  []*runtimeResource
	construction             []adapter.RuntimeResourceLease
	activate                 []func()
	abortOnce                sync.Once
	outboundManager          *outbound.Manager
	transportManager         *dns.TransportManager
	options                  option.Options
	initial                  bool
	tunDependencies          map[string]string
	stages                   [4]bool
}

func (g *preparedRuntimeGraph) releaseConstruction() {
	if g.rootSnapshot != nil {
		g.rootSnapshot.Release()
		g.rootSnapshot = nil
	}
	for _, lease := range g.construction {
		lease.Release()
	}
	g.construction = nil
}

func (g *preparedRuntimeGraph) abort() {
	g.abortOnce.Do(func() {
		if !g.published {
			postBindAbsent := g.suspendRuntimeCandidateEffects()
			_ = g.restoreRuntimeListenersWithEffects(postBindAbsent)
			g.restoreRuntimeTun()
			if g.endpointTransaction != nil {
				g.compensationError = errors.Join(g.compensationError, g.endpointTransaction.Compensate(context.Background()))
			}
			g.compensateRuntimeCertificates()
			if g.fakeIPMigration != nil {
				g.fakeIPMigration.Abort()
				g.fakeIPMigration.ActivatePersistence()
			}
		}
		for _, resource := range g.created {
			if resource.stop != nil {
				resource.stop()
			}
			if resource.stopFinal != nil {
				resource.stopFinal()
			}
		}
		if g.graph != nil {
			_ = g.graph.Discard()
		}
		for _, resource := range g.created {
			resource.owner.Seal()
		}
		g.releaseConstruction()
	})
}

// waitRuntimeResources is observation only. A timeout does not release another
// owner's leases, erase its sticky result or mark it closed.
func waitRuntimeResources(ctx context.Context, resources []*runtimeResource) error {
	for _, resource := range resources {
		if err := resource.owner.WaitClosed(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Only the preparing owner mutates producer hooks, before networkReady/publication.
func (r *runtimeResource) addRuntimeStop(producer, final func()) {
	if producer != nil {
		previous := r.stop
		r.stop = func() {
			if previous != nil {
				previous()
			}
			producer()
		}
	}
	if final != nil {
		previous := r.stopFinal
		r.stopFinal = func() {
			if previous != nil {
				previous()
			}
			final()
		}
	}
}

// Only proven-successful closed allocations leave the capacity census. Failed
// cleanup and active/retained allocations remain charged across later applies.
func (c *runtimeCoordinator) pruneRuntimeCatalogLocked() {
	for id, resource := range c.catalog {
		select {
		case <-resource.owner.Closed():
			if resource.owner.WaitClosed(context.Background()) == nil {
				delete(c.catalog, id)
			}
		default:
		}
	}
}
