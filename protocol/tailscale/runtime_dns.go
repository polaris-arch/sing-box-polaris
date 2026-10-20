//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	runtimeTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	tsDNS "github.com/sagernet/tailscale/net/dns"
	resolver "github.com/sagernet/tailscale/net/dns/resolver"
	"github.com/sagernet/tailscale/wgengine/router"
	"github.com/sagernet/tailscale/wgengine/wgcfg"

	mDNS "github.com/miekg/dns"
)

type (
	runtimeDNSSnapshotKey struct{}
	runtimeDNSSnapshot    struct {
		scope            *adapter.Scope
		ctx              context.Context
		cancel           context.CancelFunc
		carriers         *outbound.RuntimeIOFenceSet
		begin            func(context.Context) (context.Context, func(), error)
		fence            *outbound.RuntimeIOFence
		routes           map[string][]adapter.DNSTransport
		hosts            map[string][]netip.Addr
		magicHosts       resolver.MagicDNSHosts
		searchDomains    []string
		routePrefixes    []netip.Prefix
		serverAddresses  []netip.Addr
		defaultResolvers []adapter.DNSTransport
		done             chan struct{}
		err              error
	}
)

type runtimeDNSState struct {
	source     adapter.RuntimeResourceSource
	callbacks  *outbound.RuntimeIOFence
	update     sync.Mutex
	mu         sync.Mutex
	current    *runtimeDNSSnapshot
	retiring   map[*runtimeDNSSnapshot]struct{}
	stopped    bool
	unregister func()
	closeOnce  sync.Once
	closeDone  chan struct{}
	closeErr   error
	cleanupErr error
	lastChild  *Endpoint
	lastRoute  *router.Config
	lastDNS    *tsDNS.Config
}

func (t *DNSTransport) initializeRuntimeDNS() error {
	source, ok := adapter.RuntimeResourceSourceFromContext(t.ctx)
	if !ok {
		return errors.New("tailscale DNS runtime owner missing")
	}
	r := &runtimeDNSState{source: source, callbacks: outbound.NewRuntimeIOFence(nil), retiring: make(map[*runtimeDNSSnapshot]struct{}), closeDone: make(chan struct{})}
	t.runtime = r
	// The callback fence belongs to this consumer, never to the logical endpoint.
	return adapter.DeferConstructionCleanup(t.ctx, t.closeRuntimeDNS)
}

func (t *DNSTransport) startRuntimeDNS(stage adapter.StartStage) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	raw, ok := t.endpointManager.Get(t.endpointTag)
	if !ok {
		return errors.New("tailscale DNS endpoint missing")
	}
	ep, ok := raw.(*Endpoint)
	if !ok {
		return errors.New("tailscale DNS endpoint has wrong type")
	}
	r := t.runtime
	r.update.Lock()
	r.mu.Lock()
	stopped := r.stopped
	registered := r.unregister != nil
	r.mu.Unlock()
	if stopped {
		r.update.Unlock()
		return net.ErrClosed
	}
	if registered {
		r.update.Unlock()
		return nil
	}
	unregister, err := ep.registerRuntimeReconfig(r.callbacks, func(child *Endpoint, _ *wgcfg.Config, route *router.Config, dns *tsDNS.Config) {
		if err := t.reconfigureRuntimeDNS(child, route, dns); err != nil {
			ep.runtime.mu.Lock()
			ep.runtime.reconfigErr = errors.Join(ep.runtime.reconfigErr, err)
			ep.runtime.mu.Unlock()
			t.logger.Error("update Tailscale DNS: ", err)
		}
	})
	if err != nil {
		r.update.Unlock()
		return err
	}
	t.endpoint = ep
	r.mu.Lock()
	r.unregister = unregister
	r.mu.Unlock()
	r.update.Unlock()
	// A reused endpoint may already have received its only configuration event.
	// Serialize replay with the original engine callback, never with DNS update.
	child, leave, err := ep.runtimeChild(false)
	if err != nil {
		return nil
	}
	defer leave()
	child.reconfigAccess.Lock()
	defer child.reconfigAccess.Unlock()
	if child.routerCfg != nil && child.dnsCfg != nil {
		return t.reconfigureRuntimeDNS(child, child.routerCfg, child.dnsCfg)
	}
	return nil
}

// Retired snapshots leave the live configuration immediately. Their exact
// admitted invocations and actual transport cleanup remain counted until done;
// blocked original work can retain multiple historical snapshots. No cohort
// cap or premature cancellation is implied by this asynchronous retirement.
func (r *runtimeDNSState) retire(snapshot *runtimeDNSSnapshot) {
	if snapshot == nil {
		return
	}
	r.mu.Lock()
	r.retiring[snapshot] = struct{}{}
	r.mu.Unlock()
	_ = snapshot.fence.Close()
	go func() {
		snapshot.err = runtimeTLS.NewRuntimeCleanupError(errors.New("tailscale DNS snapshot cleanup did not return"))
		defer func() {
			if recover() != nil {
				snapshot.err = runtimeTLS.NewRuntimeCleanupError(errors.New("tailscale DNS snapshot cleanup panicked"))
			}
			r.mu.Lock()
			r.cleanupErr = errors.Join(r.cleanupErr, snapshot.err)
			delete(r.retiring, snapshot)
			close(snapshot.done)
			r.mu.Unlock()
		}()
		snapshot.err = errors.Join(snapshot.fence.Wait(), snapshot.scope.Close())
		snapshot.carriers.Stop()
		snapshot.err = errors.Join(snapshot.err, snapshot.carriers.Wait())
		snapshot.cancel()
	}()
}

func (t *DNSTransport) reconfigureRuntimeDNS(child *Endpoint, route *router.Config, config *tsDNS.Config) error {
	r := t.runtime
	r.update.Lock()
	defer r.update.Unlock()
	r.mu.Lock()
	stopped := r.stopped
	r.mu.Unlock()
	if stopped {
		return net.ErrClosed
	}
	if child == nil || child.runtimePhysical == nil || route == nil || config == nil {
		return errors.New("incomplete Tailscale DNS reconfiguration")
	}
	if r.lastChild == child && reflect.DeepEqual(r.lastRoute, route) && reflect.DeepEqual(r.lastDNS, config) {
		return nil
	}
	snapshotContext, cancel := context.WithCancel(t.ctx)
	snapshot := &runtimeDNSSnapshot{scope: adapter.NewScope(snapshotContext, t.logger), ctx: snapshotContext, cancel: cancel, carriers: outbound.NewRuntimeIOFenceSet(), fence: outbound.NewRuntimeIOFence(nil), routes: make(map[string][]adapter.DNSTransport), hosts: make(map[string][]netip.Addr), routePrefixes: buildRoutePrefixes(route), done: make(chan struct{})}
	// The dialer captures this logical generation and immutable routing table.
	// A logical endpoint may attach only once; daily compensation detaches a new
	// candidate and never reconstructs or retargets the old logical endpoint.
	ownedContext := adapter.ContextWithConstructionScope(snapshot.scope.Context(), snapshot.scope)
	var err error
	snapshot.begin, err = outbound.RegisterRuntimeOwnedFence(ownedContext, outbound.NewRuntimeIOFence(nil))
	if err != nil {
		cancel()
		return errors.Join(err, snapshot.scope.Close())
	}
	direct, err := dialer.NewDefault(ownedContext, option.DialerOptions{})
	if err != nil {
		cancel()
		return errors.Join(err, snapshot.scope.Close())
	}
	dnsDialer := &DNSDialer{endpoint: t.endpoint, routePrefixes: snapshot.routePrefixes, fallbackDialer: direct}
	factory := func() N.Dialer { return &runtimeDNSDialer{snapshot: snapshot, base: dnsDialer} }
	failed := func(err error) error {
		cancel()
		cleanup := snapshot.scope.Close()
		snapshot.carriers.Stop()
		cleanup = errors.Join(cleanup, snapshot.carriers.Wait())
		if cleanup != nil {
			r.mu.Lock()
			r.cleanupErr = errors.Join(r.cleanupErr, runtimeTLS.NewRuntimeCleanupError(cleanup))
			r.mu.Unlock()
		}
		return errors.Join(err, cleanup)
	}
	for domain, resolvers := range config.Routes {
		key := mDNS.CanonicalName(domain.WithTrailingDot())
		snapshot.routes[key] = nil
		for _, entry := range resolvers {
			transport, err := t.createResolver(snapshot.scope, factory, entry, t.endpoint, &runtimeDNSDialer{snapshot: snapshot, base: t.endpoint})
			if err != nil {
				return failed(err)
			}
			snapshot.routes[key] = append(snapshot.routes[key], transport)
			if address, ok := entry.IPPort(); ok {
				snapshot.serverAddresses = append(snapshot.serverAddresses, address.Addr())
			}
		}
	}
	for domain, addresses := range config.Hosts {
		snapshot.hosts[domain.WithTrailingDot()] = slices.Clone(addresses)
	}
	for _, domain := range config.SearchDomains {
		snapshot.searchDomains = append(snapshot.searchDomains, domain.WithTrailingDot())
	}
	for _, entry := range config.DefaultResolvers {
		transport, err := t.createResolver(snapshot.scope, factory, entry, t.endpoint, &runtimeDNSDialer{snapshot: snapshot, base: t.endpoint})
		if err != nil {
			return failed(err)
		}
		snapshot.defaultResolvers = append(snapshot.defaultResolvers, transport)
		if address, ok := entry.IPPort(); ok {
			snapshot.serverAddresses = append(snapshot.serverAddresses, address.Addr())
		}
	}
	snapshot.magicHosts = child.server.ExportLocalBackend().ExportMagicDNSHosts()
	r.mu.Lock()
	old := r.current
	r.current = snapshot
	r.mu.Unlock()
	t.access.Lock()
	t.routes = snapshot.routes
	t.hosts = snapshot.hosts
	t.magicHosts = snapshot.magicHosts
	t.searchDomains = snapshot.searchDomains
	t.routePrefixes = snapshot.routePrefixes
	t.serverAddresses = snapshot.serverAddresses
	t.defaultResolvers = snapshot.defaultResolvers
	t.access.Unlock()
	r.lastChild = child
	r.lastRoute = route
	r.lastDNS = config
	r.retire(old)
	return nil
}

func (r *runtimeDNSState) acquireSnapshot() (*runtimeDNSSnapshot, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped || r.current == nil {
		return nil, nil, net.ErrClosed
	}
	leave, err := r.current.fence.Acquire()
	if err != nil {
		return nil, nil, err
	}
	return r.current, leave, nil
}

func (t *DNSTransport) exchangeRuntimeDNS(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	r := t.runtime
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, r.source)
	if err != nil {
		callback(nil, err)
		return
	}
	defer release()
	snapshot, leave, err := r.acquireSnapshot()
	if err != nil {
		callback(nil, err)
		return
	}
	defer leave()
	// Both the invocation and callback have independent ownership: a synchronous
	// callback does not end an invocation that is still executing on its stack.
	callbackLeave, err := snapshot.fence.Acquire()
	if err != nil {
		callback(nil, err)
		return
	}
	ctx, callbackRelease, err := adapter.AcquireRuntimeOperation(ctx, r.source)
	if err != nil {
		callbackLeave()
		callback(nil, err)
		return
	}
	var once sync.Once
	wrapped := func(response *mDNS.Msg, err error) {
		once.Do(func() { defer callbackLeave(); defer callbackRelease(); callback(response, err) })
	}
	combined, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	stop := context.AfterFunc(snapshot.ctx, func() { defer close(finished); cancel() })
	original := wrapped
	wrapped = func(response *mDNS.Msg, err error) {
		defer cancel()
		defer func() {
			if !stop() {
				<-finished
			}
		}()
		original(response, err)
	}
	ctx = context.WithValue(combined, runtimeDNSSnapshotKey{}, snapshot)
	t.exchangeAsync(ctx, message, wrapped)
}

func (t *DNSTransport) resetRuntimeDNS() {
	snapshot, leave, err := t.runtime.acquireSnapshot()
	if err != nil {
		return
	}
	defer leave()
	for _, list := range snapshot.routes {
		for _, transport := range list {
			transport.Reset()
		}
	}
	for _, transport := range snapshot.defaultResolvers {
		transport.Reset()
	}
}

func (t *DNSTransport) closeRuntimeDNS() error {
	r := t.runtime
	r.closeOnce.Do(func() {
		t.idleWork.Seal()
		t.idleWork.Wait()
		r.closeErr = runtimeTLS.NewRuntimeCleanupError(errors.New("tailscale DNS cleanup did not return"))
		defer close(r.closeDone)
		r.mu.Lock()
		r.stopped = true
		unregister := r.unregister
		r.mu.Unlock()
		if unregister != nil {
			unregister()
		}
		_ = r.callbacks.Close()
		// Join the exact callback before draining its last published snapshot.
		callbackErr := r.callbacks.Wait()
		r.update.Lock()
		r.mu.Lock()
		current := r.current
		r.current = nil
		r.mu.Unlock()
		r.retire(current)
		r.mu.Lock()
		for snapshot := range r.retiring {
			snapshot.cancel()
		}
		r.mu.Unlock()
		r.update.Unlock()
		for {
			r.mu.Lock()
			var pending *runtimeDNSSnapshot
			for snapshot := range r.retiring {
				pending = snapshot
				break
			}
			r.mu.Unlock()
			if pending == nil {
				break
			}
			<-pending.done
		}
		r.mu.Lock()
		r.closeErr = errors.Join(callbackErr, r.cleanupErr)
		r.mu.Unlock()
		t.idleAccess.Lock()
		r.closeErr = errors.Join(r.closeErr, t.idleCleanupErr)
		t.idleAccess.Unlock()
		if r.closeErr != nil {
			r.closeErr = runtimeTLS.NewRuntimeCleanupError(r.closeErr)
		}
	})
	<-r.closeDone
	return r.closeErr
}

// Resolver-owned idle carriers cannot keep their own graph alive. Their exact
// scope joins all native resolver work, then joins every original carrier.
type runtimeDNSDialer struct {
	snapshot *runtimeDNSSnapshot
	base     N.Dialer
}

func (d *runtimeDNSDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	s := d.snapshot
	creation, err := s.carriers.Begin()
	if err != nil {
		return nil, err
	}
	defer creation.Done()
	ctx, leave, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	raw, err := d.base.DialContext(ctx, network, address)
	if raw == nil {
		return nil, err
	}
	conn, fence := outbound.WrapRuntimeOwnedConn(raw)
	registerErr := creation.Register(fence)
	if err != nil || registerErr != nil || s.ctx.Err() != nil {
		return nil, errors.Join(err, registerErr, s.ctx.Err(), fence.RuntimeCloseAndWait())
	}
	return conn, nil
}

func (d *runtimeDNSDialer) ListenPacket(ctx context.Context, address M.Socksaddr) (net.PacketConn, error) {
	s := d.snapshot
	creation, err := s.carriers.Begin()
	if err != nil {
		return nil, err
	}
	defer creation.Done()
	ctx, leave, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	raw, err := d.base.ListenPacket(ctx, address)
	if raw == nil {
		return nil, err
	}
	conn, fence := outbound.WrapRuntimeOwnedPacketConn(raw)
	registerErr := creation.Register(fence)
	if err != nil || registerErr != nil || s.ctx.Err() != nil {
		return nil, errors.Join(err, registerErr, s.ctx.Err(), fence.RuntimeCloseAndWait())
	}
	return conn, nil
}

// Idle policy covers all children owned by this wrapper, including candidates
// and retired cohorts whose in-flight queries have not finished. It never uses
// Reset: only each child knows which carriers are currently idle.
func (t *DNSTransport) SetKeepIdleConnections(keep bool) {
	done, ok := t.idleWork.Reserve()
	if !ok {
		return
	}
	defer done()
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	t.disableIdleConnections = !keep
	for resolver := range t.idleResolvers {
		resolver.SetKeepIdleConnections(keep)
	}
}

func (t *DNSTransport) CloseIdleConnections() {
	done, ok := t.idleWork.Reserve()
	if !ok {
		return
	}
	defer done()
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	for resolver := range t.idleResolvers {
		resolver.CloseIdleConnections()
	}
}

// The private start scope is not published until Start returns. This prevents
// a retiring owner from closing a partly initialized child and losing a cleanup
// registered by Start after the owner's scope has already drained.
func (t *DNSTransport) startDNSResolver(resolver adapter.DNSTransport, scope *adapter.Scope) error {
	done, ok := t.idleWork.Reserve()
	if !ok {
		return lifecycle.ErrStopped
	}
	defer done()
	keeper, ok := resolver.(adapter.IdleConnectionKeeper)
	if !ok {
		return errors.New("endpoint DNS resolver requires idle-only connection control")
	}
	childScope := adapter.NewScope(scope.Context(), t.logger)
	startErr := resolver.Start(adapter.StartStateStart, childScope)
	if startErr == nil {
		// Registration and policy application are atomic with a concurrent
		// setter, and complete before route/default publication.
		t.idleAccess.Lock()
		keeper.SetKeepIdleConnections(!t.disableIdleConnections)
		if t.idleResolvers == nil {
			t.idleResolvers = make(map[adapter.IdleConnectionKeeper]struct{})
		}
		t.idleResolvers[keeper] = struct{}{}
		t.idleAccess.Unlock()
	}
	cleanupErr := adapter.DeferConstructionCleanup(adapter.ContextWithConstructionScope(context.Background(), scope), func() error {
		// Serialize removal with admitted idle calls, then close outside the
		// registry lock. New callers can no longer reach this child.
		t.idleAccess.Lock()
		delete(t.idleResolvers, keeper)
		t.idleAccess.Unlock()
		err := lifecycle.Uncertain("endpoint DNS child resolver", childScope.Close())
		if err != nil {
			t.idleAccess.Lock()
			t.idleCleanupErr = errors.Join(t.idleCleanupErr, err)
			t.idleAccess.Unlock()
		}
		return err
	})
	return errors.Join(startErr, cleanupErr, scope.Context().Err())
}
