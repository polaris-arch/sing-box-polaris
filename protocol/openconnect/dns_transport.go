package openconnect

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	openconnecttransport "github.com/sagernet/sing-box/transport/openconnect"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

func RegisterDNSTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.OpenConnectDNSServerOptions](registry, C.DNSTypeOpenConnect, NewDNSTransport)
}

type DNSTransport struct {
	idleAccess             sync.Mutex
	disableIdleConnections bool
	idleResolvers          map[adapter.IdleConnectionKeeper]struct{}
	idleCleanupErr         error
	work                   lifecycle.Work
	producers              lifecycle.Work
	scopes                 lifecycle.Scopes
	resource               adapter.RuntimeResourceSource
	operationCtx           context.Context
	operationCancel        context.CancelFunc
	producerCtx            context.Context
	producerCancel         context.CancelFunc
	closeOnce              sync.Once
	closeErr               error
	constructionOwned      bool
	endpointUnlink         func()
	startOnce              sync.Once
	startErr               error

	dns.TransportAdapter
	ctx                    context.Context
	logger                 logger.ContextLogger
	endpointTag            string
	acceptDefaultResolvers bool
	acceptSearchDomain     bool
	endpointManager        adapter.EndpointManager
	dialer                 N.Dialer
	access                 sync.RWMutex
	updateAccess           sync.Mutex
	closed                 bool
	routes                 []openConnectDNSRoute
	searchDomains          []string
	serverAddresses        []netip.Addr
	defaultResolvers       []adapter.DNSTransport
	resolverScope          *adapter.Scope
}

type openConnectDNSRoute struct {
	domain    string
	resolvers []adapter.DNSTransport
}

func NewDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.OpenConnectDNSServerOptions) (adapter.DNSTransport, error) {
	if options.Endpoint == "" {
		return nil, E.New("missing endpoint tag")
	}
	t := &DNSTransport{
		TransportAdapter:       dns.NewTransportAdapter(C.DNSTypeOpenConnect, tag, nil),
		ctx:                    ctx,
		logger:                 logger,
		endpointTag:            options.Endpoint,
		acceptDefaultResolvers: options.AcceptDefaultResolvers,
		acceptSearchDomain:     options.AcceptSearchDomain,
		endpointManager:        service.FromContext[adapter.EndpointManager](ctx),
	}
	t.resource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	t.operationCtx, t.operationCancel = context.WithCancel(ctx)
	t.producerCtx, t.producerCancel = context.WithCancel(t.operationCtx)
	var err error
	t.constructionOwned, err = lifecycle.ConstructionCleanup(ctx, t.close)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *DNSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	t.startOnce.Do(func() {
		if !t.constructionOwned {
			_, t.startErr = lifecycle.ConstructionCleanup(adapter.ContextWithConstructionScope(context.Background(), scope), t.close)
		}
	})
	if t.startErr != nil {
		return t.startErr
	}
	done, ok := t.work.Reserve()
	if !ok {
		return lifecycle.ErrStopped
	}
	defer done()

	if stage != adapter.StartStateInitialize {
		return nil
	}
	rawEndpoint, loaded := t.endpointManager.Get(t.endpointTag)
	if !loaded {
		return E.New("endpoint not found: ", t.endpointTag)
	}
	openConnectEndpoint, isOpenConnect := rawEndpoint.(*Endpoint)
	if !isOpenConnect {
		return E.New("endpoint is not OpenConnect: ", t.endpointTag)
	}
	if t.resource != nil && (openConnectEndpoint.runtime == nil || openConnectEndpoint.runtime.source.ID() != t.resource.ID()) {
		return E.New("endpoint DNS callback requires the same runtime resource cohort")
	}
	if openConnectEndpoint.runtime != nil {
		t.producerCtx, t.endpointUnlink = lifecycle.LinkCancellation(t.producerCtx, openConnectEndpoint.runtime.ctx)
	}

	openConnectEndpoint.dnsTransportAccess.Lock()
	if openConnectEndpoint.dnsTransport != nil && openConnectEndpoint.dnsTransport.Tag() != t.Tag() {
		openConnectEndpoint.dnsTransportAccess.Unlock()
		return E.New("only one DNS server is allowed for an endpoint")
	}
	openConnectEndpoint.dnsTransport = t
	scope.Add(func() error {
		openConnectEndpoint.dnsTransportAccess.Lock()
		if openConnectEndpoint.dnsTransport == t {
			openConnectEndpoint.dnsTransport = nil
		}
		openConnectEndpoint.dnsTransportAccess.Unlock()
		return nil
	})
	t.dialer = openConnectEndpoint
	state := openConnectEndpoint.state.Load()
	if state.started && state.tunnelConfigured && openConnectEndpoint.client.Ready() {
		t.updateConfiguration(state.configuration)
	}
	openConnectEndpoint.dnsTransportAccess.Unlock()
	return nil
}

func (t *DNSTransport) updateConfiguration(configuration openconnecttransport.Configuration) {
	done, ok := t.producers.Reserve()
	if !ok {
		return
	}
	defer done()
	t.updateAccess.Lock()
	defer t.updateAccess.Unlock()
	if err := t.scopes.WaitReady(t.producerCtx); err != nil {
		return
	}

	resolverByAddress := make(map[netip.Addr]adapter.DNSTransport)
	var serverAddresses []netip.Addr
	resolverFor := func(address netip.Addr) adapter.DNSTransport {
		if !address.IsValid() {
			return nil
		}
		resolver, loaded := resolverByAddress[address]
		if loaded {
			return resolver
		}
		serverAddresses = append(serverAddresses, address)
		resolver = transport.NewUDPRaw(
			t.logger,
			dns.NewTransportAdapter(C.DNSTypeUDP, t.Tag()+"/"+address.String(), nil),
			t.dialer,
			M.SocksaddrFrom(address, 53),
		)
		resolverByAddress[address] = resolver
		return resolver
	}
	resolversFor := func(addresses []netip.Addr) []adapter.DNSTransport {
		resolvers := make([]adapter.DNSTransport, 0, len(addresses))
		resolverSet := make(map[adapter.DNSTransport]bool)
		for _, address := range addresses {
			resolver := resolverFor(address)
			if resolver != nil && !resolverSet[resolver] {
				resolverSet[resolver] = true
				resolvers = append(resolvers, resolver)
			}
		}
		return resolvers
	}
	defaultResolvers := resolversFor(configuration.DNS)
	routes := make([]openConnectDNSRoute, 0, len(configuration.SplitDNS)+len(configuration.SearchDomains)+len(configuration.SplitDNSRules))
	routeIndex := make(map[string]int)
	for _, rule := range configuration.SplitDNSRules {
		resolvers := resolversFor(rule.Servers)
		for _, domain := range rule.Domains {
			canonicalDomain := canonicalOpenConnectDomain(domain)
			if canonicalDomain != "" {
				fqdn := mDNS.Fqdn(canonicalDomain)
				index, loaded := routeIndex[fqdn]
				if loaded {
					resolverSet := make(map[adapter.DNSTransport]bool)
					for _, resolver := range routes[index].resolvers {
						resolverSet[resolver] = true
					}
					for _, resolver := range resolvers {
						if !resolverSet[resolver] {
							routes[index].resolvers = append(routes[index].resolvers, resolver)
						}
					}
				} else {
					routeIndex[fqdn] = len(routes)
					routes = append(routes, openConnectDNSRoute{domain: fqdn, resolvers: resolvers})
				}
			}
		}
	}
	for _, domain := range append(append([]string(nil), configuration.SplitDNS...), configuration.SearchDomains...) {
		canonicalDomain := canonicalOpenConnectDomain(domain)
		if canonicalDomain != "" {
			fqdn := mDNS.Fqdn(canonicalDomain)
			_, loaded := routeIndex[fqdn]
			if !loaded {
				routeIndex[fqdn] = len(routes)
				routes = append(routes, openConnectDNSRoute{domain: fqdn, resolvers: defaultResolvers})
			}
		}
	}
	searchDomains := make([]string, 0, len(configuration.SearchDomains))
	searchDomainSet := make(map[string]bool)
	for _, domain := range configuration.SearchDomains {
		canonicalDomain := canonicalOpenConnectDomain(domain)
		if canonicalDomain != "" {
			fqdn := mDNS.Fqdn(canonicalDomain)
			if !searchDomainSet[fqdn] {
				searchDomainSet[fqdn] = true
				searchDomains = append(searchDomains, fqdn)
			}
		}
	}
	if !t.acceptDefaultResolvers || !configuration.TunnelAllDNS && (len(configuration.SplitDNS) > 0 || len(configuration.SplitDNSRules) > 0) {
		defaultResolvers = nil
	}

	resolverScope, scopeErr := t.scopes.New(t.operationCtx, t.logger)
	if scopeErr != nil {
		return
	}
	for _, resolver := range resolverByAddress {
		err := t.startDNSResolver(resolver, resolverScope)
		if err != nil {
			t.scopes.Retire(resolverScope)
			t.logger.Error(E.Cause(err, "start DNS resolver"))
			return
		}
	}
	t.access.Lock()
	if t.closed {
		t.access.Unlock()
		t.scopes.Retire(resolverScope)
		return
	}
	oldResolverScope := t.resolverScope
	t.routes = routes
	t.searchDomains = searchDomains
	t.serverAddresses = serverAddresses
	t.defaultResolvers = defaultResolvers
	t.resolverScope = resolverScope
	t.access.Unlock()
	if oldResolverScope != nil {
		t.scopes.Retire(oldResolverScope)
	}
	if len(resolverByAddress) > 0 {
		t.logger.Info("updated ", len(routes), " DNS routes and ", len(resolverByAddress), " resolvers")
	} else {
		t.logger.Info("cleared DNS configuration")
	}
}

func (t *DNSTransport) Reset() {
	_, done, err := t.work.Operation(context.Background(), t.resource)
	if err != nil {
		return
	}
	defer done()
	t.access.RLock()
	resolvers := t.collectResolversLocked()
	t.access.RUnlock()
	for _, resolver := range resolvers {
		resolver.Reset()
	}
}

func (t *DNSTransport) ServerAddresses() []netip.Addr {
	_, done, err := t.work.Operation(context.Background(), t.resource)
	if err != nil {
		return nil
	}
	defer done()
	t.access.RLock()
	defer t.access.RUnlock()
	return append([]netip.Addr(nil), t.serverAddresses...)
}

func (t *DNSTransport) SearchDomains() []string {
	_, done, err := t.work.Operation(context.Background(), t.resource)
	if err != nil {
		return nil
	}
	defer done()
	t.access.RLock()
	defer t.access.RUnlock()
	return append([]string(nil), t.searchDomains...)
}

func (t *DNSTransport) PreferredDomain(domain string) bool {
	_, done, err := t.work.Operation(context.Background(), t.resource)
	if err != nil {
		return false
	}
	defer done()
	canonicalDomain := mDNS.Fqdn(canonicalOpenConnectDomain(domain))
	t.access.RLock()
	routes := t.routes
	t.access.RUnlock()
	for _, route := range routes {
		if mDNS.IsSubDomain(route.domain, canonicalDomain) {
			return true
		}
	}
	return false
}

func (t *DNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	done := make(chan struct{})
	var response *mDNS.Msg
	var err error
	t.ExchangeAsync(ctx, message, func(callbackResponse *mDNS.Msg, callbackErr error) {
		response = callbackResponse
		err = callbackErr
		close(done)
	})
	<-done
	return response, err
}

func (t *DNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	ctx, releaseCall, err := t.work.Operation(ctx, t.resource)
	if err != nil {
		callback(nil, err)
		return
	}
	defer releaseCall()
	ctx, releaseCallback, err := t.work.Operation(ctx, t.resource)
	if err != nil {
		callback(nil, err)
		return
	}
	ctx, unlink := lifecycle.LinkCancellation(ctx, t.operationCtx)
	original := callback
	var called atomic.Bool
	callback = func(response *mDNS.Msg, err error) {
		if !called.CompareAndSwap(false, true) {
			return
		}
		defer releaseCallback()
		defer unlink()
		original(response, err)
	}

	if len(message.Question) != 1 {
		callback(nil, os.ErrInvalid)
		return
	}
	t.access.RLock()
	searchDomains := append([]string(nil), t.searchDomains...)
	t.access.RUnlock()
	if t.acceptSearchDomain && len(searchDomains) > 0 && mDNS.CountLabel(message.Question[0].Name) == 1 {
		t.exchangeWithSearchDomains(ctx, message, searchDomains, callback)
		return
	}
	t.exchangeOnce(ctx, message, callback)
}

func (t *DNSTransport) exchangeWithSearchDomains(ctx context.Context, message *mDNS.Msg, searchDomains []string, callback func(response *mDNS.Msg, err error)) {
	originalQuestion := message.Question[0]
	singleLabel := strings.TrimSuffix(originalQuestion.Name, ".")
	exchangers := make([]transport.AsyncExchanger, 0, len(searchDomains)+1)
	for _, searchDomain := range searchDomains {
		expandedName := singleLabel + "." + searchDomain
		exchangers = append(exchangers, func(exchangeCtx context.Context, exchangeCallback func(response *mDNS.Msg, err error)) {
			question := originalQuestion
			question.Name = expandedName
			rewritten := *message
			rewritten.Question = []mDNS.Question{question}
			t.exchangeOnce(exchangeCtx, &rewritten, func(response *mDNS.Msg, err error) {
				if err == nil {
					restoreOpenConnectDNSQuestion(response, expandedName, originalQuestion)
				}
				exchangeCallback(response, err)
			})
		})
	}
	exchangers = append(exchangers, func(exchangeCtx context.Context, exchangeCallback func(response *mDNS.Msg, err error)) {
		t.exchangeOnce(exchangeCtx, message, exchangeCallback)
	})
	transport.ExchangeSequential(ctx, exchangers, func(response *mDNS.Msg, err error) bool {
		return err == nil && response.Rcode != mDNS.RcodeNameError
	}, callback)
}

func restoreOpenConnectDNSQuestion(response *mDNS.Msg, expandedName string, originalQuestion mDNS.Question) {
	response.Question = []mDNS.Question{originalQuestion}
	for _, record := range response.Answer {
		if strings.EqualFold(record.Header().Name, expandedName) {
			record.Header().Name = originalQuestion.Name
		}
	}
}

func (t *DNSTransport) exchangeOnce(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	question := message.Question[0]
	t.access.RLock()
	routes := t.routes
	defaultResolvers := t.defaultResolvers
	t.access.RUnlock()
	var matchedResolvers []adapter.DNSTransport
	matchedDomainLength := -1
	for _, route := range routes {
		if len(route.domain) > matchedDomainLength && mDNS.IsSubDomain(route.domain, question.Name) {
			matchedDomainLength = len(route.domain)
			matchedResolvers = route.resolvers
		}
	}
	if matchedDomainLength != -1 {
		if len(matchedResolvers) == 0 {
			callback(nil, dns.RcodeNameError)
			return
		}
		transport.ExchangeSequential(ctx, openConnectDNSExchangers(matchedResolvers, message), nil, callback)
		return
	}
	if len(defaultResolvers) == 0 {
		callback(nil, dns.RcodeNameError)
		return
	}
	transport.ExchangeSequential(ctx, openConnectDNSExchangers(defaultResolvers, message), nil, callback)
}

func openConnectDNSExchangers(resolvers []adapter.DNSTransport, message *mDNS.Msg) []transport.AsyncExchanger {
	return common.Map(resolvers, func(resolver adapter.DNSTransport) transport.AsyncExchanger {
		return func(ctx context.Context, callback func(response *mDNS.Msg, err error)) {
			resolver.ExchangeAsync(ctx, message, callback)
		}
	})
}

func (t *DNSTransport) collectResolversLocked() []adapter.DNSTransport {
	resolverSet := make(map[adapter.DNSTransport]bool)
	for _, route := range t.routes {
		for _, resolver := range route.resolvers {
			resolverSet[resolver] = true
		}
	}
	for _, resolver := range t.defaultResolvers {
		resolverSet[resolver] = true
	}
	resolvers := make([]adapter.DNSTransport, 0, len(resolverSet))
	for resolver := range resolverSet {
		resolvers = append(resolvers, resolver)
	}
	return resolvers
}

var (
	_ adapter.IdleConnectionKeeper            = (*DNSTransport)(nil)
	_ adapter.DNSTransportWithPreferredDomain = (*DNSTransport)(nil)
	_ adapter.DNSTransportWithConfiguration   = (*DNSTransport)(nil)
)
