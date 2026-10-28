package local

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"github.com/godbus/dbus/v5"
	mDNS "github.com/miekg/dns"
)

func isSystemdResolvedManaged() bool {
	resolvContent, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false
	}
	defer resolvContent.Close()
	scanner := bufio.NewScanner(resolvContent)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '#' {
			return false
		}
		if strings.Contains(line, "systemd-resolved") {
			return true
		}
	}
	return false
}

type DBusResolvedResolver struct {
	work             lifecycle.Work
	producers        lifecycle.Work
	serverScopes     lifecycle.Scopes
	producersStopped atomic.Bool
	runtimeResource  adapter.RuntimeResourceSource
	operationCtx     context.Context
	operationCancel  context.CancelFunc
	producerCtx      context.Context
	producerCancel   context.CancelFunc
	closeOnce        sync.Once
	closeDone        chan struct{}
	closeErr         error

	ctx               context.Context
	logger            logger.ContextLogger
	interfaceFinder   control.InterfaceFinder
	interfaceMonitor  tun.DefaultInterfaceMonitor
	interfaceCallback *list.Element[tun.DefaultInterfaceUpdateCallback]
	networkMonitor    tun.NetworkUpdateMonitor
	networkCallback   *list.Element[tun.NetworkUpdateCallback]
	systemBus         *dbus.Conn
	savedServerSet    atomic.Pointer[resolvedServerSet]
	refresh           lifecycle.CoalescedRefresh
	updateRunAccess   sync.Mutex
	closed            bool
	idleAccess        sync.Mutex
	idleDisabled      bool
}

type resolvedServerSet struct {
	scopes          []*resolvedScope
	serverAddresses []netip.Addr
	signature       []string
	serverScope     *adapter.Scope
}

// Match levels of dns_scope_good_domain() in systemd-resolved: a routing or search
// domain match yields its label count, and only scopes at the best level are queried.
const (
	resolvedScopeNoMatch    = -3
	resolvedScopeLastResort = -2
	resolvedScopeMaybe      = -1
)

// systemd-resolved only signals changes of the DNS server list, while clients such as
// NetworkManager and systemd-networkd configure domains, default route and DNS over TLS
// of a link in separate calls right after it; link state changes are not signaled at all.
const resolvedUpdateDelay = time.Second

// SD_RESOLVED_DNS bit of org.freedesktop.resolve1.Link.ScopesMask, set when the link has a unicast DNS scope.
const resolvedScopesMaskDNS = 1 << 0

// TRANSACTION_UDP_TIMEOUT_USEC in systemd-resolved (resolved-timeouts.h), after which a transaction
// is resent to the next server of the scope.
const resolvedServerTimeout = 5 * time.Second

type resolvedScope struct {
	domains       []string
	defaultRoute  bool
	fallback      bool
	servers       []resolvedServer
	currentServer atomic.Uint32
}

type resolvedServer struct {
	primaryTransport  adapter.DNSTransport
	fallbackTransport adapter.DNSTransport
}

type resolvedScopeSpecification struct {
	interfaceName  string
	dnsOverTLSMode string
	domains        []string
	defaultRoute   bool
	fallback       bool
	servers        []resolvedServerSpecification
}

type resolvedServerSpecification struct {
	address    netip.Addr
	port       uint16
	serverName string
}

type resolvedManagerDNS struct {
	InterfaceIndex int32
	Family         int32
	Address        []byte
}

type resolvedManagerDNSEx struct {
	InterfaceIndex int32
	Family         int32
	Address        []byte
	Port           uint16
	Name           string
}

type resolvedManagerDomain struct {
	InterfaceIndex int32
	Domain         string
	RoutingOnly    bool
}

type resolvedManagerServer struct {
	interfaceIndex int32
	address        []byte
	port           uint16
	serverName     string
}

func NewResolvedResolver(ctx context.Context, logger logger.ContextLogger) (ResolvedResolver, error) {
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	interfaceMonitor := networkManager.InterfaceMonitor()
	if interfaceMonitor == nil {
		return nil, os.ErrInvalid
	}
	operationCtx, operationCancel := context.WithCancel(ctx)
	producerCtx, producerCancel := context.WithCancel(operationCtx)
	systemBus, err := dbus.ConnectSystemBus(dbus.WithContext(operationCtx))
	if err != nil {
		producerCancel()
		operationCancel()
		return nil, err
	}
	resource, _ := adapter.RuntimeResourceSourceFromContext(ctx)
	return &DBusResolvedResolver{
		runtimeResource: resource,
		operationCtx:    operationCtx, operationCancel: operationCancel,
		producerCtx: producerCtx, producerCancel: producerCancel,
		closeDone:        make(chan struct{}),
		ctx:              ctx,
		logger:           logger,
		interfaceFinder:  networkManager.InterfaceFinder(),
		interfaceMonitor: interfaceMonitor,
		networkMonitor:   networkManager.NetworkMonitor(),
		systemBus:        systemBus,
	}, nil
}

func (t *DBusResolvedResolver) Start() error {
	done, ok := t.work.Reserve()
	if !ok {
		return lifecycle.ErrStopped
	}
	defer done()
	t.updateStatus(t.operationCtx)
	t.interfaceCallback = t.interfaceMonitor.RegisterCallback(t.updateDefaultInterface)
	if t.networkMonitor != nil {
		t.networkCallback = t.networkMonitor.RegisterCallback(t.postUpdateStatus)
	}
	err := t.systemBus.AddMatchSignalContext(t.operationCtx,
		dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
		dbus.WithMatchSender("org.freedesktop.DBus"),
		dbus.WithMatchArg(0, "org.freedesktop.resolve1"),
	)
	if err != nil {
		return E.Cause(err, "configure resolved restart listener")
	}
	err = t.systemBus.AddMatchSignalContext(t.operationCtx,
		dbus.WithMatchInterface("org.freedesktop.DBus.Properties"),
		dbus.WithMatchMember("PropertiesChanged"),
		dbus.WithMatchSender("org.freedesktop.resolve1"),
		dbus.WithMatchArg(0, "org.freedesktop.resolve1.Manager"),
	)
	if err != nil {
		return E.Cause(err, "configure resolved properties listener")
	}
	if !t.producers.Go(t.loopUpdateStatus) {
		return lifecycle.ErrStopped
	}
	return nil
}

// The private bus exports no user methods or interceptors. Its only path back
// into this resolver is our signal channel and synchronous CallWithContext
// stacks. Close terminates the default signal handler (including deferred
// channel deliveries), and our Work/producer joins drain those receiving paths.
// A remaining godbus reader/cancellation tail touches only the private Conn and
// its call/channel state; it has no callable path to a retired graph dependency.
func (t *DBusResolvedResolver) StopRuntimeProducers() {
	t.producersStopped.Store(true)
	stopResolvedProducers(t.savedServerSet.Load())
	t.producers.Seal()
	t.producerCancel()
}

func (t *DBusResolvedResolver) StopRuntimeOperations() {
	t.closeOnce.Do(func() {
		t.work.Seal()
		t.operationCancel()
		t.StopRuntimeProducers()
		go func() {
			defer close(t.closeDone)
			t.closeErr = lifecycle.CleanupResult("resolved resolver", func() error {
				closeErr := lifecycle.Uncertain("private resolved DBus connection", t.systemBus.Close())
				t.work.Wait()
				if t.interfaceCallback != nil {
					t.interfaceMonitor.UnregisterCallback(t.interfaceCallback)
				}
				if t.networkCallback != nil {
					t.networkMonitor.UnregisterCallback(t.networkCallback)
				}
				t.producers.Wait()
				t.updateRunAccess.Lock()
				t.closed = true
				t.savedServerSet.Store(nil)
				t.updateRunAccess.Unlock()
				closeErr = E.Errors(closeErr, t.serverScopes.Close())
				return closeErr
			})
		}()
	})
}

func (t *DBusResolvedResolver) Close() error {
	t.StopRuntimeOperations()
	<-t.closeDone
	return t.closeErr
}

func (t *DBusResolvedResolver) Reset() {
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return
	}
	defer done()
	serverSet := t.savedServerSet.Load()
	if serverSet == nil {
		return
	}
	for _, scope := range serverSet.scopes {
		for _, server := range scope.servers {
			server.primaryTransport.Reset()
			if server.fallbackTransport != nil {
				server.fallbackTransport.Reset()
			}
		}
	}
}

func (t *DBusResolvedResolver) Environment() []string {
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return nil
	}
	defer done()
	serverSet := t.savedServerSet.Load()
	if serverSet == nil {
		return nil
	}
	return serverSet.signature
}

func (t *DBusResolvedResolver) ServerAddresses() []netip.Addr {
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return nil
	}
	defer done()
	serverSet := t.savedServerSet.Load()
	if serverSet == nil {
		return nil
	}
	return serverSet.serverAddresses
}

func (t *DBusResolvedResolver) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	ctx, callDone, err := t.work.Operation(ctx, t.runtimeResource)
	if err != nil {
		callback(nil, err)
		return
	}
	defer callDone()
	ctx, callbackDone, err := t.work.Operation(ctx, t.runtimeResource)
	if err != nil {
		callback(nil, err)
		return
	}
	ctx, unlink := lifecycle.LinkCancellation(ctx, t.operationCtx)
	originalCallback := callback
	var called atomic.Bool
	callback = func(response *mDNS.Msg, err error) {
		if !called.CompareAndSwap(false, true) {
			return
		}
		defer callbackDone()
		defer unlink()
		originalCallback(response, err)
	}
	serverSet := t.savedServerSet.Load()
	if serverSet == nil {
		if !t.work.Go(func() {
			err := t.updateStatus(ctx)
			if err != nil {
				callback(nil, err)
				return
			}
			t.exchangeServerSet(ctx, message, t.savedServerSet.Load(), callback)
		}) {
			callback(nil, lifecycle.ErrStopped)
		}
		return
	}
	t.exchangeServerSet(ctx, message, serverSet, func(response *mDNS.Msg, err error) {
		if err == nil {
			callback(response, nil)
			return
		}
		if !t.work.Go(func() {
			t.updateStatus(ctx)
			refreshedServerSet := t.savedServerSet.Load()
			if refreshedServerSet == nil || refreshedServerSet == serverSet {
				callback(nil, err)
				return
			}
			t.exchangeServerSet(ctx, message, refreshedServerSet, callback)
		}) {
			callback(nil, lifecycle.ErrStopped)
		}
	})
}

func (t *DBusResolvedResolver) exchangeServerSet(ctx context.Context, message *mDNS.Msg, serverSet *resolvedServerSet, callback func(response *mDNS.Msg, err error)) {
	if serverSet == nil {
		callback(nil, os.ErrClosed)
		return
	}
	scopes := serverSet.selectScopes(message.Question[0].Name)
	if len(scopes) == 0 {
		callback(nil, E.New("no appropriate name servers or networks for name found"))
		return
	}
	scopeExchangers := common.Map(scopes, func(scope *resolvedScope) dnsTransport.AsyncExchanger {
		return func(exchangeCtx context.Context, exchangeCallback func(response *mDNS.Msg, err error)) {
			scope.exchange(exchangeCtx, message, exchangeCallback)
		}
	})
	dnsTransport.ExchangeParallel(ctx, scopeExchangers, acceptResolvedScopeResponse, callback)
}

func (s *resolvedScope) exchange(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	serverCount := uint32(len(s.servers))
	currentServer := s.currentServer.Load()
	serverExchangers := make([]dnsTransport.AsyncExchanger, 0, serverCount)
	for i := range serverCount {
		serverIndex := (currentServer + i) % serverCount
		server := s.servers[serverIndex]
		serverExchangers = append(serverExchangers, func(exchangeCtx context.Context, exchangeCallback func(response *mDNS.Msg, err error)) {
			server.exchange(exchangeCtx, message, func(response *mDNS.Msg, err error) {
				if exchangeCtx.Err() == nil && !acceptResolvedServerResponse(response, err) {
					s.currentServer.CompareAndSwap(serverIndex, (serverIndex+1)%serverCount)
				}
				exchangeCallback(response, err)
			})
		})
	}
	dnsTransport.ExchangeSequential(ctx, serverExchangers, acceptResolvedServerResponse, callback)
}

func (s *resolvedServer) exchange(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	exchangeResolvedTransport(ctx, s.primaryTransport, message, func(response *mDNS.Msg, err error) {
		if err != nil && s.fallbackTransport != nil {
			exchangeResolvedTransport(ctx, s.fallbackTransport, message, callback)
			return
		}
		callback(response, err)
	})
}

func exchangeResolvedTransport(ctx context.Context, transport adapter.DNSTransport, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	exchangeCtx, cancel := context.WithTimeout(ctx, resolvedServerTimeout)
	transport.ExchangeAsync(exchangeCtx, message, func(response *mDNS.Msg, err error) {
		cancel()
		callback(response, err)
	})
}

// systemd-resolved starts a query on every scope at the best match level at once
// (resolved-dns-query.c dns_query_go_scopes) and completes it with the first positive answer
// (dns_query_ready). Within a scope, SERVFAIL and timeouts move the scope to its next server, which
// later queries start from (resolved-dns-transaction.c dns_transaction_retry).
func acceptResolvedServerResponse(response *mDNS.Msg, err error) bool {
	return err == nil && response.Rcode != mDNS.RcodeServerFailure
}

func acceptResolvedScopeResponse(response *mDNS.Msg, err error) bool {
	return err == nil && response.Rcode == mDNS.RcodeSuccess
}

func (s *resolvedServerSet) selectScopes(name string) []*resolvedScope {
	var (
		bestMatch      = resolvedScopeNoMatch
		selectedScopes []*resolvedScope
	)
	for _, scope := range s.scopes {
		match := scope.match(name)
		if match == resolvedScopeNoMatch || match < bestMatch {
			continue
		}
		if match > bestMatch {
			bestMatch = match
			selectedScopes = selectedScopes[:0]
		}
		selectedScopes = append(selectedScopes, scope)
	}
	return selectedScopes
}

func (s *resolvedScope) match(name string) int {
	bestLabels := -1
	for _, domain := range s.domains {
		if mDNS.IsSubDomain(domain, name) {
			bestLabels = max(bestLabels, mDNS.CountLabel(domain))
		}
	}
	if bestLabels >= 0 {
		return bestLabels
	}
	if !s.defaultRoute {
		return resolvedScopeNoMatch
	}
	if s.fallback {
		return resolvedScopeLastResort
	}
	return resolvedScopeMaybe
}

func (t *DBusResolvedResolver) loopUpdateStatus() {
	signalChan := make(chan *dbus.Signal, 1)
	t.systemBus.Signal(signalChan)
	defer t.systemBus.RemoveSignal(signalChan)
	for {
		var signal *dbus.Signal
		select {
		case <-t.producerCtx.Done():
			return
		case next, ok := <-signalChan:
			if !ok {
				return
			}
			signal = next
		}
		switch signal.Name {
		case "org.freedesktop.DBus.NameOwnerChanged":
			if len(signal.Body) != 3 {
				continue
			}
			newOwner, loaded := signal.Body[2].(string)
			if !loaded || newOwner == "" {
				continue
			}
			t.postUpdateStatus()
		case "org.freedesktop.DBus.Properties.PropertiesChanged":
			if !shouldUpdateResolvedServerSet(signal) {
				continue
			}
			t.postUpdateStatus()
		}
	}
}

func (t *DBusResolvedResolver) postUpdateStatus() {
	t.refresh.Request(&t.producers, t.producerCtx, resolvedUpdateDelay, t.serverScopes.WaitReady, func(ctx context.Context) bool {
		return errors.Is(t.updateStatus(ctx), lifecycle.ErrSocketCohortBusy)
	})
}

func (t *DBusResolvedResolver) updateStatus(ctx context.Context) error {
	t.updateRunAccess.Lock()
	defer t.updateRunAccess.Unlock()
	if t.closed {
		return os.ErrClosed
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	serverSet, err := t.checkResolved(ctx)
	if t.closed || ctx.Err() != nil {
		if serverSet != nil {
			t.serverScopes.Retire(serverSet.serverScope)
		}
		if t.closed {
			return os.ErrClosed
		}
		return ctx.Err()
	}
	if err != nil {
		var dbusErr dbus.Error
		if !errors.As(err, &dbusErr) || dbusErr.Name != "org.freedesktop.DBus.Error.NameHasNoOwner" {
			// A failed candidate (including a full retirement cohort queue)
			// must not discard the working resolver. Only an authoritative
			// service disappearance retires it without a replacement.
			if serverSet != nil {
				t.serverScopes.Retire(serverSet.serverScope)
			}
			if errors.Is(err, lifecycle.ErrSocketCohortBusy) {
				t.postUpdateStatus()
			}
			t.logger.Debug(E.Cause(err, "systemd-resolved refresh failed; retaining current servers"))
			return err
		}
	}
	oldServerSet := t.swapIdleServerSet(serverSet)
	if t.producersStopped.Load() {
		stopResolvedProducers(serverSet)
	}
	if oldServerSet != nil {
		t.serverScopes.Retire(oldServerSet.serverScope)
	}
	if err != nil {
		var dbusErr dbus.Error
		if !errors.As(err, &dbusErr) || dbusErr.Name != "org.freedesktop.DBus.Error.NameHasNoOwner" {
			t.logger.Debug(E.Cause(err, "systemd-resolved service unavailable"))
		}
		if oldServerSet != nil {
			t.logger.Debug("systemd-resolved service is gone")
		}
		return err
	} else if oldServerSet == nil {
		t.logger.Debug("using systemd-resolved service as resolver")
	}
	return nil
}

func (t *DBusResolvedResolver) checkResolved(ctx context.Context) (*resolvedServerSet, error) {
	managerObject := t.systemBus.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	err := managerObject.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0).Err
	if err != nil {
		return nil, err
	}
	defaultInterface := t.interfaceMonitor.DefaultInterface()
	if defaultInterface == nil {
		return nil, E.New("missing default interface")
	}
	managerProperties, err := loadResolvedProperties(ctx, managerObject, "org.freedesktop.resolve1.Manager")
	if err != nil {
		return nil, err
	}
	servers, err := loadResolvedManagerServers(managerProperties, "DNS")
	if err != nil {
		return nil, err
	}
	var managerDomains []resolvedManagerDomain
	err = storeResolvedProperty(managerProperties, "Domains", &managerDomains)
	if err != nil {
		return nil, err
	}
	var dnsOverTLSMode string
	err = storeResolvedProperty(managerProperties, "DNSOverTLS", &dnsOverTLSMode)
	if err != nil {
		return nil, err
	}
	globalScope := resolvedScopeSpecification{
		interfaceName:  defaultInterface.Name,
		dnsOverTLSMode: dnsOverTLSMode,
		defaultRoute:   true,
	}
	var linkScopes []resolvedScopeSpecification
	linkScopeIndexes := make(map[int32]int)
	for _, server := range servers {
		if server.interfaceIndex == 0 {
			serverSpecification, loaded := buildResolvedServerSpecification(globalScope.interfaceName, server)
			if loaded {
				globalScope.servers = append(globalScope.servers, serverSpecification)
			}
			continue
		}
		scopeIndex, loaded := linkScopeIndexes[server.interfaceIndex]
		if !loaded {
			linkScope, linkLoaded, linkErr := t.loadResolvedLinkScope(ctx, managerObject, server.interfaceIndex)
			if linkErr != nil {
				return nil, linkErr
			}
			if !linkLoaded {
				linkScopeIndexes[server.interfaceIndex] = -1
				continue
			}
			scopeIndex = len(linkScopes)
			linkScopeIndexes[server.interfaceIndex] = scopeIndex
			linkScopes = append(linkScopes, linkScope)
		} else if scopeIndex < 0 {
			continue
		}
		serverSpecification, loaded := buildResolvedServerSpecification(linkScopes[scopeIndex].interfaceName, server)
		if loaded {
			linkScopes[scopeIndex].servers = append(linkScopes[scopeIndex].servers, serverSpecification)
		}
	}
	for _, domain := range managerDomains {
		domainName := mDNS.Fqdn(domain.Domain)
		if domain.InterfaceIndex == 0 {
			globalScope.domains = append(globalScope.domains, domainName)
			continue
		}
		scopeIndex, loaded := linkScopeIndexes[domain.InterfaceIndex]
		if loaded && scopeIndex >= 0 {
			linkScopes[scopeIndex].domains = append(linkScopes[scopeIndex].domains, domainName)
		}
	}
	if len(globalScope.servers) == 0 && !slices.ContainsFunc(linkScopes, func(it resolvedScopeSpecification) bool {
		return it.defaultRoute && len(it.servers) > 0
	}) {
		fallbackServers, fallbackErr := loadResolvedManagerServers(managerProperties, "FallbackDNS")
		if fallbackErr != nil {
			return nil, fallbackErr
		}
		for _, server := range fallbackServers {
			serverSpecification, loaded := buildResolvedServerSpecification(globalScope.interfaceName, server)
			if loaded {
				globalScope.servers = append(globalScope.servers, serverSpecification)
			}
		}
		globalScope.fallback = true
	}
	scopeSpecifications := common.Filter(append([]resolvedScopeSpecification{globalScope}, linkScopes...), func(it resolvedScopeSpecification) bool {
		return len(it.servers) > 0
	})
	if len(scopeSpecifications) == 0 {
		return nil, E.New("no DNS servers configured")
	}
	serverScope, err := t.serverScopes.New(t.operationCtx, t.logger)
	if err != nil {
		return nil, err
	}
	serverSet := &resolvedServerSet{serverScope: serverScope}
	for _, scopeSpecification := range scopeSpecifications {
		scope, createErr := t.createResolvedScope(serverSet.serverScope, scopeSpecification)
		if createErr != nil {
			t.serverScopes.Retire(serverSet.serverScope)
			return nil, createErr
		}
		serverSet.scopes = append(serverSet.scopes, scope)
		for _, serverSpecification := range scopeSpecification.servers {
			serverSet.serverAddresses = append(serverSet.serverAddresses, serverSpecification.address)
			serverSet.signature = append(serverSet.signature, scopeSpecification.interfaceName+"/"+M.SocksaddrFrom(serverSpecification.address, serverSpecification.port).String())
		}
	}
	return serverSet, nil
}

func (t *DBusResolvedResolver) loadResolvedLinkScope(ctx context.Context, managerObject dbus.BusObject, interfaceIndex int32) (resolvedScopeSpecification, bool, error) {
	linkInterface, err := t.interfaceFinder.ByIndex(int(interfaceIndex))
	if err != nil || slices.Contains(t.interfaceMonitor.MyInterfaces(), linkInterface.Name) {
		return resolvedScopeSpecification{}, false, nil
	}
	var linkPath dbus.ObjectPath
	err = managerObject.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.GetLink", 0, interfaceIndex).Store(&linkPath)
	if err != nil {
		return resolvedScopeSpecification{}, false, err
	}
	linkProperties, err := loadResolvedProperties(ctx, t.systemBus.Object("org.freedesktop.resolve1", linkPath), "org.freedesktop.resolve1.Link")
	if err != nil {
		return resolvedScopeSpecification{}, false, err
	}
	var scopesMask uint64
	err = storeResolvedProperty(linkProperties, "ScopesMask", &scopesMask)
	if err != nil {
		return resolvedScopeSpecification{}, false, err
	}
	if scopesMask&resolvedScopesMaskDNS == 0 {
		return resolvedScopeSpecification{}, false, nil
	}
	linkScope := resolvedScopeSpecification{
		interfaceName: linkInterface.Name,
	}
	err = storeResolvedProperty(linkProperties, "DNSOverTLS", &linkScope.dnsOverTLSMode)
	if err != nil {
		return resolvedScopeSpecification{}, false, err
	}
	err = storeResolvedProperty(linkProperties, "DefaultRoute", &linkScope.defaultRoute)
	if err != nil {
		return resolvedScopeSpecification{}, false, err
	}
	return linkScope, true, nil
}

func (t *DBusResolvedResolver) createResolvedScope(serverScope *adapter.Scope, scopeSpecification resolvedScopeSpecification) (*resolvedScope, error) {
	scope := &resolvedScope{
		domains:      scopeSpecification.domains,
		defaultRoute: scopeSpecification.defaultRoute,
		fallback:     scopeSpecification.fallback,
	}
	serverDialer, err := dialer.NewDefault(t.ctx, option.DialerOptions{
		BindInterface:      scopeSpecification.interfaceName,
		UDPFragmentDefault: true,
	})
	if err != nil {
		return nil, err
	}
	for _, serverSpecification := range scopeSpecification.servers {
		server, createErr := t.createResolvedServer(serverScope, serverDialer, scopeSpecification.dnsOverTLSMode, serverSpecification)
		if createErr != nil {
			return nil, createErr
		}
		scope.servers = append(scope.servers, server)
	}
	return scope, nil
}

func (t *DBusResolvedResolver) createResolvedServer(serverScope *adapter.Scope, serverDialer N.Dialer, dnsOverTLSMode string, serverSpecification resolvedServerSpecification) (resolvedServer, error) {
	if dnsOverTLSMode == "yes" {
		primaryTransport, err := t.createResolvedTransport(serverScope, serverDialer, serverSpecification, true)
		if err != nil {
			return resolvedServer{}, err
		}
		return resolvedServer{
			primaryTransport: primaryTransport,
		}, nil
	}
	if dnsOverTLSMode == "opportunistic" {
		primaryTransport, err := t.createResolvedTransport(serverScope, serverDialer, serverSpecification, true)
		if err != nil {
			return resolvedServer{}, err
		}
		fallbackTransport, err := t.createResolvedTransport(serverScope, serverDialer, serverSpecification, false)
		if err != nil {
			return resolvedServer{}, err
		}
		return resolvedServer{
			primaryTransport:  primaryTransport,
			fallbackTransport: fallbackTransport,
		}, nil
	}
	primaryTransport, err := t.createResolvedTransport(serverScope, serverDialer, serverSpecification, false)
	if err != nil {
		return resolvedServer{}, err
	}
	return resolvedServer{
		primaryTransport: primaryTransport,
	}, nil
}

func (t *DBusResolvedResolver) createResolvedTransport(serverScope *adapter.Scope, serverDialer N.Dialer, serverSpecification resolvedServerSpecification, useTLS bool) (adapter.DNSTransport, error) {
	serverAddress := M.SocksaddrFrom(serverSpecification.address, resolvedServerPort(serverSpecification.port, useTLS))
	if useTLS {
		tlsAddress := serverSpecification.address
		if tlsAddress.Zone() != "" {
			tlsAddress = tlsAddress.WithZone("")
		}
		serverName := serverSpecification.serverName
		if serverName == "" {
			serverName = tlsAddress.String()
		}
		tlsConfig, err := tls.NewClient(adapter.ContextWithConstructionScope(t.operationCtx, serverScope), t.logger, tlsAddress.String(), option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: serverName,
		})
		if err != nil {
			return nil, err
		}
		serverTransport := dnsTransport.NewTLSRaw(t.logger, dns.NewTransportAdapter(C.DNSTypeTLS, "", nil), serverDialer, serverAddress, tlsConfig)
		err = serverTransport.Start(adapter.StartStateStart, serverScope)
		if err != nil {
			return nil, err
		}
		return serverTransport, nil
	}
	serverTransport := dnsTransport.NewUDPRaw(t.logger, dns.NewTransportAdapter(C.DNSTypeUDP, "", nil), serverDialer, serverAddress)
	err := serverTransport.Start(adapter.StartStateStart, serverScope)
	if err != nil {
		return nil, err
	}
	return serverTransport, nil
}

func buildResolvedServerSpecification(interfaceName string, server resolvedManagerServer) (resolvedServerSpecification, bool) {
	address, loaded := netip.AddrFromSlice(server.address)
	if !loaded {
		return resolvedServerSpecification{}, false
	}
	if address.Is6() && address.IsLinkLocalUnicast() && address.Zone() == "" {
		address = address.WithZone(interfaceName)
	}
	return resolvedServerSpecification{
		address:    address,
		port:       server.port,
		serverName: server.serverName,
	}, true
}

func resolvedServerPort(port uint16, useTLS bool) uint16 {
	if port > 0 {
		return port
	}
	if useTLS {
		return 853
	}
	return 53
}

func loadResolvedProperties(ctx context.Context, object dbus.BusObject, interfaceName string) (map[string]dbus.Variant, error) {
	var properties map[string]dbus.Variant
	err := object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, interfaceName).Store(&properties)
	if err != nil {
		return nil, E.Cause(err, "load ", interfaceName, " properties")
	}
	return properties, nil
}

func storeResolvedProperty(properties map[string]dbus.Variant, name string, value any) error {
	property, loaded := properties[name]
	if !loaded {
		return nil
	}
	err := property.Store(value)
	if err != nil {
		return E.Cause(err, "parse resolved property ", name)
	}
	return nil
}

func loadResolvedManagerServers(properties map[string]dbus.Variant, name string) ([]resolvedManagerServer, error) {
	_, loaded := properties[name+"Ex"]
	if loaded {
		var serversEx []resolvedManagerDNSEx
		err := storeResolvedProperty(properties, name+"Ex", &serversEx)
		if err != nil {
			return nil, err
		}
		return common.Map(serversEx, func(it resolvedManagerDNSEx) resolvedManagerServer {
			return resolvedManagerServer{
				interfaceIndex: it.InterfaceIndex,
				address:        it.Address,
				port:           it.Port,
				serverName:     it.Name,
			}
		}), nil
	}
	var servers []resolvedManagerDNS
	err := storeResolvedProperty(properties, name, &servers)
	if err != nil {
		return nil, err
	}
	return common.Map(servers, func(it resolvedManagerDNS) resolvedManagerServer {
		return resolvedManagerServer{
			interfaceIndex: it.InterfaceIndex,
			address:        it.Address,
		}
	}), nil
}

func shouldUpdateResolvedServerSet(signal *dbus.Signal) bool {
	if len(signal.Body) != 3 {
		return true
	}
	changedProperties, loaded := signal.Body[1].(map[string]dbus.Variant)
	if !loaded {
		return true
	}
	for propertyName := range changedProperties {
		switch propertyName {
		case "DNS", "DNSEx", "DNSOverTLS":
			return true
		}
	}
	invalidatedProperties, loaded := signal.Body[2].([]string)
	if !loaded {
		return true
	}
	for _, propertyName := range invalidatedProperties {
		switch propertyName {
		case "DNS", "DNSEx", "DNSOverTLS":
			return true
		}
	}
	return false
}

func (t *DBusResolvedResolver) updateDefaultInterface(defaultInterface *control.Interface, flags int) {
	t.postUpdateStatus()
}

func stopResolvedProducers(set *resolvedServerSet) {
	if set == nil {
		return
	}
	for _, scope := range set.scopes {
		for _, server := range scope.servers {
			if producer, ok := server.primaryTransport.(interface{ StopRuntimeProducers() }); ok {
				producer.StopRuntimeProducers()
			}
			if producer, ok := server.fallbackTransport.(interface{ StopRuntimeProducers() }); ok {
				producer.StopRuntimeProducers()
			}
		}
	}
}
