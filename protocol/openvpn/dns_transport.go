package openvpn

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	boxDNS "github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	ovpntransport "github.com/sagernet/sing-box/transport/openvpn"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"golang.org/x/net/http2"
)

func RegisterDNSTransport(registry *boxDNS.TransportRegistry) {
	boxDNS.RegisterTransport[option.OpenVPNDNSServerOptions](registry, C.DNSTypeOpenVPN, NewDNSTransport)
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

	boxDNS.TransportAdapter
	ctx                    context.Context
	logger                 logger.ContextLogger
	endpointTag            string
	acceptDefaultResolvers bool
	acceptSearchDomain     bool
	endpointManager        adapter.EndpointManager
	dialer                 N.Dialer
	updateAccess           sync.Mutex
	access                 sync.RWMutex
	closed                 bool
	routes                 map[string][]adapter.DNSTransport
	searchDomains          []string
	serverAddresses        []netip.Addr
	defaultResolvers       []adapter.DNSTransport
	resolverScope          *adapter.Scope
}

func NewDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.OpenVPNDNSServerOptions) (adapter.DNSTransport, error) {
	if options.Endpoint == "" {
		return nil, E.New("missing endpoint tag")
	}
	t := &DNSTransport{
		TransportAdapter:       boxDNS.NewTransportAdapter(C.DNSTypeOpenVPN, tag, nil),
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
	endpoint, isOpenVPN := rawEndpoint.(*ClientEndpoint)
	if !isOpenVPN {
		return E.New("endpoint is not an OpenVPN client: ", t.endpointTag)
	}
	if t.resource != nil && (endpoint.runtime == nil || endpoint.runtime.source.ID() != t.resource.ID()) {
		return E.New("endpoint DNS callback requires the same runtime resource cohort")
	}
	if endpoint.runtime != nil {
		t.producerCtx, t.endpointUnlink = lifecycle.LinkCancellation(t.producerCtx, endpoint.runtime.ctx)
	}
	t.dialer = endpoint

	err := endpoint.installDNSTransport(t)
	if err != nil {
		return err
	}
	scope.Add(func() error {
		endpoint.uninstallDNSTransport(t)
		return nil
	})
	return nil
}

func (t *DNSTransport) onReconfiguration(configuration ovpntransport.Configuration) {
	err := t.updateResolvers(configuration)
	if err != nil && !E.IsClosed(err) {
		t.logger.Error(E.Cause(err, "update DNS resolvers"))
	}
}

func (t *DNSTransport) updateResolvers(configuration ovpntransport.Configuration) error {
	done, ok := t.producers.Reserve()
	if !ok {
		return lifecycle.ErrStopped
	}
	defer done()

	t.updateAccess.Lock()
	defer t.updateAccess.Unlock()
	t.access.RLock()
	closed := t.closed
	t.access.RUnlock()
	if closed {
		return net.ErrClosed
	}
	routes := make(map[string][]adapter.DNSTransport)
	searchDomains := normalizeOpenVPNDomains(configuration.SearchDomains)
	var defaultResolvers []adapter.DNSTransport
	if err := t.scopes.WaitReady(t.producerCtx); err != nil {
		return err
	}
	resolverScope, scopeErr := t.scopes.New(t.operationCtx, t.logger)
	if scopeErr != nil {
		return scopeErr
	}
	servers := slices.Clone(configuration.DNSServers)
	slices.SortFunc(servers, func(left ovpntransport.DNSServer, right ovpntransport.DNSServer) int {
		return left.Priority - right.Priority
	})
	var selectedResolvers []adapter.DNSTransport
	var serverAddresses []netip.Addr
	if len(servers) > 0 {
		server := servers[0]
		if server.DNSSEC == "yes" {
			return t.failResolverUpdate(resolverScope, E.New("DNSSEC validation is required but is not supported"))
		}
		for _, address := range server.Addresses {
			resolver, err := t.createResolver(resolverScope, server, address)
			if err != nil {
				return t.failResolverUpdate(resolverScope, err)
			}
			err = t.startDNSResolver(resolver, resolverScope)
			if err != nil {
				return t.failResolverUpdate(resolverScope, err)
			}
			selectedResolvers = append(selectedResolvers, resolver)
			serverAddresses = append(serverAddresses, address.Addr())
		}
		if len(selectedResolvers) == 0 {
			return t.failResolverUpdate(resolverScope, E.New("DNS server ", server.Priority, " has no addresses"))
		}
		if len(server.ResolveDomains) == 0 {
			defaultResolvers = slices.Clone(selectedResolvers)
		} else {
			for _, domain := range server.ResolveDomains {
				normalizedDomain := normalizeOpenVPNDomain(domain)
				if normalizedDomain != "" {
					routes[normalizedDomain] = slices.Clone(selectedResolvers)
				}
			}
		}
	} else {
		for _, address := range configuration.DNS {
			resolver := dnsTransport.NewUDPRaw(t.logger, t.TransportAdapter, t.dialer, M.SocksaddrFrom(address, 53))
			err := t.startDNSResolver(resolver, resolverScope)
			if err != nil {
				return t.failResolverUpdate(resolverScope, err)
			}
			selectedResolvers = append(selectedResolvers, resolver)
			serverAddresses = append(serverAddresses, address)
		}
		if len(configuration.DNSRoutes) > 0 {
			if len(selectedResolvers) == 0 {
				return t.failResolverUpdate(resolverScope, E.New("DOMAIN-ROUTE requires traditional pushed DNS servers"))
			}
			for _, domain := range configuration.DNSRoutes {
				normalizedDomain := normalizeOpenVPNDomain(domain)
				if normalizedDomain != "" {
					routes[normalizedDomain] = slices.Clone(selectedResolvers)
				}
			}
		} else {
			defaultResolvers = slices.Clone(selectedResolvers)
		}
	}
	if len(searchDomains) > 0 && len(selectedResolvers) == 0 {
		return t.failResolverUpdate(resolverScope, E.New("search domains require pushed DNS servers"))
	}
	for _, searchDomain := range searchDomains {
		routes[searchDomain] = slices.Clone(selectedResolvers)
	}

	t.access.Lock()
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
	t.logger.Info("updated ", len(routes), " DNS routes, ", len(searchDomains), " search domains and ", len(defaultResolvers), " default resolvers")
	return nil
}

func (t *DNSTransport) failResolverUpdate(resolverScope *adapter.Scope, updateErr error) error {
	t.scopes.Retire(resolverScope)
	t.access.Lock()
	oldResolverScope := t.resolverScope
	t.routes = nil
	t.searchDomains = nil
	t.serverAddresses = nil
	t.defaultResolvers = nil
	t.resolverScope = nil
	t.access.Unlock()
	if oldResolverScope != nil {
		t.scopes.Retire(oldResolverScope)
	}
	return updateErr
}

func (t *DNSTransport) createResolver(resolverScope *adapter.Scope, server ovpntransport.DNSServer, address netip.AddrPort) (adapter.DNSTransport, error) {
	transportType := strings.ToLower(server.Transport)
	if transportType == "" {
		transportType = "plain"
	}
	port := address.Port()
	switch transportType {
	case "plain":
		if port == 0 {
			port = 53
		}
		return dnsTransport.NewUDPRaw(t.logger, t.TransportAdapter, t.dialer, M.SocksaddrFrom(address.Addr(), port)), nil
	case "dot", "doh":
	default:
		return nil, E.New("unsupported DNS transport: ", server.Transport)
	}
	serverName := server.SNI
	if serverName == "" {
		serverName = address.Addr().String()
	}
	if transportType == "dot" {
		if port == 0 {
			port = 853
		}
		tlsConfig, err := boxTLS.NewClient(adapter.ContextWithConstructionScope(t.operationCtx, resolverScope), t.logger, serverName, option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: serverName,
		})
		if err != nil {
			return nil, err
		}
		return dnsTransport.NewTLSRaw(t.logger, t.TransportAdapter, t.dialer, M.SocksaddrFrom(address.Addr(), port), tlsConfig), nil
	}
	if port == 0 {
		port = 443
	}
	tlsConfig, err := boxTLS.NewClient(adapter.ContextWithConstructionScope(t.operationCtx, resolverScope), t.logger, serverName, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		ALPN:       []string{http2.NextProtoTLS, "http/1.1"},
	})
	if err != nil {
		return nil, err
	}
	host := serverName
	if port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	destination := &url.URL{Scheme: "https", Host: host, Path: "/dns-query"}
	return dnsTransport.NewHTTPSRaw(t.TransportAdapter, t.logger, t.dialer, destination, http.Header{}, M.SocksaddrFrom(address.Addr(), port), tlsConfig), nil
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

func (t *DNSTransport) Raw() bool {
	return true
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
	t.access.RLock()
	defer t.access.RUnlock()
	for route := range t.routes {
		if openVPNDomainMatches(route, domain) {
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
	searchDomains := slices.Clone(t.searchDomains)
	t.access.RUnlock()
	if t.acceptSearchDomain && len(searchDomains) > 0 && mDNS.CountLabel(message.Question[0].Name) == 1 {
		t.exchangeWithSearchDomains(ctx, message, searchDomains, callback)
		return
	}
	t.exchangeOnce(ctx, message, t.acceptDefaultResolvers, callback)
}

func (t *DNSTransport) exchangeWithSearchDomains(ctx context.Context, message *mDNS.Msg, searchDomains []string, callback func(response *mDNS.Msg, err error)) {
	originalQuestion := message.Question[0]
	singleLabel := strings.TrimSuffix(originalQuestion.Name, ".")
	exchangers := make([]dnsTransport.AsyncExchanger, 0, len(searchDomains)+1)
	for _, searchDomain := range searchDomains {
		expandedName := singleLabel + "." + searchDomain
		exchangers = append(exchangers, func(exchangeCtx context.Context, exchangeCallback func(response *mDNS.Msg, err error)) {
			question := originalQuestion
			question.Name = expandedName
			rewritten := *message
			rewritten.Question = []mDNS.Question{question}
			t.exchangeOnce(exchangeCtx, &rewritten, false, func(response *mDNS.Msg, err error) {
				if err == nil {
					restoreOpenVPNOriginalQuestion(response, expandedName, originalQuestion)
				}
				exchangeCallback(response, err)
			})
		})
	}
	exchangers = append(exchangers, func(exchangeCtx context.Context, exchangeCallback func(response *mDNS.Msg, err error)) {
		t.exchangeOnce(exchangeCtx, message, t.acceptDefaultResolvers, exchangeCallback)
	})
	dnsTransport.ExchangeSequential(ctx, exchangers, func(response *mDNS.Msg, err error) bool {
		return err == nil && response.Rcode != mDNS.RcodeNameError
	}, callback)
}

func (t *DNSTransport) exchangeOnce(ctx context.Context, message *mDNS.Msg, allowDefaultResolvers bool, callback func(response *mDNS.Msg, err error)) {
	question := message.Question[0]
	t.access.RLock()
	var matchedResolvers []adapter.DNSTransport
	matchedLength := -1
	for route, resolvers := range t.routes {
		if openVPNDomainMatches(route, question.Name) && len(route) > matchedLength {
			matchedLength = len(route)
			matchedResolvers = resolvers
		}
	}
	defaultResolvers := slices.Clone(t.defaultResolvers)
	t.access.RUnlock()
	if len(matchedResolvers) > 0 {
		dnsTransport.ExchangeSequential(ctx, openVPNResolverExchangers(matchedResolvers, message), nil, callback)
		return
	}
	if allowDefaultResolvers && len(defaultResolvers) > 0 {
		dnsTransport.ExchangeSequential(ctx, openVPNResolverExchangers(defaultResolvers, message), nil, callback)
		return
	}
	callback(nil, boxDNS.RcodeNameError)
}

func openVPNResolverExchangers(resolvers []adapter.DNSTransport, message *mDNS.Msg) []dnsTransport.AsyncExchanger {
	return common.Map(resolvers, func(resolver adapter.DNSTransport) dnsTransport.AsyncExchanger {
		return func(ctx context.Context, callback func(response *mDNS.Msg, err error)) {
			resolver.ExchangeAsync(ctx, message, callback)
		}
	})
}

func (t *DNSTransport) collectResolversLocked() []adapter.DNSTransport {
	var resolvers []adapter.DNSTransport
	for _, routeResolvers := range t.routes {
		resolvers = append(resolvers, routeResolvers...)
	}
	resolvers = append(resolvers, t.defaultResolvers...)
	return common.Uniq(resolvers)
}

func normalizeOpenVPNDomain(domain string) string {
	normalized := strings.TrimSpace(strings.ToLower(domain))
	if normalized == "." {
		return normalized
	}
	normalized = strings.TrimSuffix(normalized, ".")
	if normalized == "" {
		return ""
	}
	return normalized + "."
}

func normalizeOpenVPNDomains(domains []string) []string {
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		normalizedDomain := normalizeOpenVPNDomain(domain)
		if normalizedDomain != "" && normalizedDomain != "." && !slices.Contains(normalized, normalizedDomain) {
			normalized = append(normalized, normalizedDomain)
		}
	}
	return normalized
}

func restoreOpenVPNOriginalQuestion(response *mDNS.Msg, expandedName string, originalQuestion mDNS.Question) {
	response.Question = []mDNS.Question{originalQuestion}
	for _, resourceRecord := range response.Answer {
		if strings.EqualFold(resourceRecord.Header().Name, expandedName) {
			resourceRecord.Header().Name = originalQuestion.Name
		}
	}
}

var (
	_ adapter.IdleConnectionKeeper            = (*DNSTransport)(nil)
	_ adapter.DNSTransportWithPreferredDomain = (*DNSTransport)(nil)
	_ adapter.DNSTransportWithConfiguration   = (*DNSTransport)(nil)
)
