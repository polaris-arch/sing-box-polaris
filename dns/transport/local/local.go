package local

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing-box/dns/transport/local/systemconfig"
	"github.com/sagernet/sing-box/dns/transport/mdns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.LocalDNSServerOptions](registry, C.DNSTypeLocal, NewTransport)
}

var (
	_ adapter.DNSTransport                    = (*Transport)(nil)
	_ adapter.DNSTransportWithPreferredDomain = (*Transport)(nil)
	_ adapter.DNSTransportWithConfiguration   = (*Transport)(nil)
	_ adapter.DNSTransportWithEnvironment     = (*Transport)(nil)
)

type Transport struct {
	work               lifecycle.Work
	runtimeResource    adapter.RuntimeResourceSource
	operationCtx       context.Context
	operationCancel    context.CancelFunc
	runtimeOnce        sync.Once
	startOnce          sync.Once
	startErr           error
	closeOnce          sync.Once
	closeErr           error
	constructionOwned  bool
	serverScopes       lifecycle.Scopes
	refresh            lifecycle.CoalescedRefresh
	producers          lifecycle.Work
	producerCtx        context.Context
	producerCancel     context.CancelFunc
	producersStopped   atomic.Bool
	runtimeStateAccess sync.Mutex
	dns.TransportAdapter
	ctx               context.Context
	logger            logger.ContextLogger
	preferredResolver *PreferredDomainResolver
	dialer            N.Dialer
	preferGo          bool
	resolved          ResolvedResolver
	mdnsTransport     adapter.DNSTransport
	mdnsScope         *adapter.Scope
	configSource      *systemconfig.Source
	system            systemResolver
	serverSet         atomic.Pointer[localServerSet]
	serverSetAccess   sync.Mutex
	idleAccess        sync.Mutex
	idleDisabled      bool
}

// closeConfigSource is replaced by tests.
var closeConfigSource = (*systemconfig.Source).Close

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.LocalDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewLocalDialer(ctx, options)
	if err != nil {
		return nil, err
	}
	preferredResolver, err := NewPreferredDomainResolver(ctx, logger, options)
	if err != nil {
		return nil, err
	}
	configSource := systemconfig.NewSource(ctx)
	t := &Transport{
		TransportAdapter:  dns.NewTransportAdapterWithLocalOptions(C.DNSTypeLocal, tag, options),
		ctx:               ctx,
		logger:            logger,
		preferredResolver: preferredResolver,
		dialer:            transportDialer,
		preferGo:          options.PreferGo,
		configSource:      configSource,
	}
	t.initRuntime()
	t.constructionOwned, err = lifecycle.ConstructionCleanup(ctx, t.close)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Transport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	t.initRuntime()
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
	if scope.Context().Err() != nil {
		return scope.Context().Err()
	}
	t.preferredResolver.Start(stage)
	switch stage {
	case adapter.StartStateInitialize:
		if !t.preferGo && isSystemdResolvedManaged() {
			resolvedResolver, err := NewResolvedResolver(adapter.ContextWithRuntimeOwnership(t.operationCtx, t.ctx), t.logger)
			if err == nil {
				t.installResolved(resolvedResolver)
				err = resolvedResolver.Start()
				if err == nil {
					t.installResolved(resolvedResolver)
				} else {
					closeErr := resolvedResolver.Close()
					if closeErr != nil {
						return E.Errors(err, closeErr)
					}
					t.installResolved(nil)
					t.logger.Warn(E.Cause(err, "initialize resolved resolver"))
				}
			}
		}
	case adapter.StartStateStart:
		if !C.IsDarwin {
			t.mdnsTransport = mdns.NewRawTransport(t.TransportAdapter, t.operationCtx, t.logger)
			t.mdnsScope = adapter.NewScope(t.ctx, t.logger)
		}
		fallthrough
	default:
		if t.mdnsTransport != nil {
			err := t.mdnsTransport.Start(stage, t.mdnsScope)
			if err != nil {
				return err
			}
		}
	}
	if t.work.Sealed() {
		return lifecycle.ErrStopped
	}
	return scope.Context().Err()
}

func (t *Transport) Reset() {
	t.initRuntime()
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return
	}
	defer done()
	serverSet := t.serverSet.Load()
	if serverSet != nil {
		for _, serverTransport := range serverSet.transports {
			serverTransport.Reset()
		}
	}
	t.system.reset()
	t.configSource.Reset()
	if t.resolved != nil {
		t.resolved.Reset()
	}
	if t.mdnsTransport != nil {
		t.mdnsTransport.Reset()
	}
}

func (t *Transport) PreferredDomain(domain string) bool {
	t.initRuntime()
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return false
	}
	defer done()
	return t.preferredResolver.PreferredDomain(domain)
}

func (t *Transport) ServerAddresses() []netip.Addr {
	t.initRuntime()
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return nil
	}
	defer done()
	if t.resolved != nil {
		return t.resolved.ServerAddresses()
	}
	return common.Map(t.configSource.Configuration().Servers, func(it M.Socksaddr) netip.Addr {
		return it.Addr
	})
}

func (t *Transport) SearchDomains() []string {
	t.initRuntime()
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return nil
	}
	defer done()
	return t.configSource.Configuration().Search
}

func (t *Transport) Environment() []string {
	t.initRuntime()
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return nil
	}
	defer done()
	if t.resolved != nil {
		return t.resolved.Environment()
	}
	return t.configSource.Configuration().Signature()
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	done := make(chan struct{})
	var (
		response *mDNS.Msg
		err      error
	)
	t.ExchangeAsync(ctx, message, func(callbackResponse *mDNS.Msg, callbackErr error) {
		response = callbackResponse
		err = callbackErr
		close(done)
	})
	<-done
	return response, err
}

func (t *Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	t.initRuntime()
	ctx, releaseCall, err := t.work.Operation(ctx, t.runtimeResource)
	if err != nil {
		callback(nil, err)
		return
	}
	defer releaseCall()
	ctx, releaseCallback, err := t.work.Operation(ctx, t.runtimeResource)
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
		defer releaseCallback()
		defer unlink()
		originalCallback(response, err)
	}
	question := message.Question[0]
	response := t.preferredResolver.Lookup(message)
	if response != nil {
		callback(response, nil)
		return
	}
	if mdns.IsLocalDomain(question.Name) {
		if C.IsDarwin {
			t.systemExchangeAsync(ctx, message, callback)
			return
		}
		t.mdnsTransport.ExchangeAsync(ctx, message, callback)
		return
	}
	if t.resolved != nil {
		t.resolved.ExchangeAsync(ctx, message, callback)
		return
	}
	t.exchangeAsync(ctx, message, searchName(question.Name), callback)
}

func (t *Transport) initRuntime() {
	t.runtimeOnce.Do(func() {
		ctx := t.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		t.runtimeResource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
		t.operationCtx, t.operationCancel = context.WithCancel(ctx)
		t.producerCtx, t.producerCancel = context.WithCancel(t.operationCtx)
	})
}

func (t *Transport) StopRuntimeProducers() {
	t.initRuntime()
	t.producers.Seal()
	t.producerCancel()
	t.producersStopped.Store(true)
	if set := t.serverSet.Load(); set != nil {
		for _, server := range set.transports {
			if producer, ok := server.(interface{ StopRuntimeProducers() }); ok {
				producer.StopRuntimeProducers()
			}
		}
	}
	t.runtimeStateAccess.Lock()
	resolved := t.resolved
	t.runtimeStateAccess.Unlock()
	if producer, ok := resolved.(interface{ StopRuntimeProducers() }); ok {
		producer.StopRuntimeProducers()
	}
}

func (t *Transport) StopRuntimeOperations() {
	t.initRuntime()
	t.work.Seal()
	t.operationCancel()
	t.system.stop()
	t.runtimeStateAccess.Lock()
	resolved := t.resolved
	t.runtimeStateAccess.Unlock()
	if stopper, ok := resolved.(interface{ StopRuntimeOperations() }); ok {
		stopper.StopRuntimeOperations()
	}
	t.StopRuntimeProducers()
	// Cancellation reaches admitted raw UDP/TCP requests through their caller
	// context. Socket cohorts are joined only after construction stacks finish.
}

func (t *Transport) close() error {
	t.closeOnce.Do(func() {
		t.StopRuntimeOperations()
		t.work.Wait()
		t.producers.Wait()
		t.closeErr = E.Errors(t.closeErr, t.system.close())
		if t.resolved != nil {
			t.closeErr = E.Errors(t.closeErr, lifecycle.Uncertain("resolved resolver", t.resolved.Close()))
		}
		if t.mdnsScope != nil {
			t.closeErr = E.Errors(t.closeErr, lifecycle.Uncertain("local mDNS", t.mdnsScope.Close()))
		}
		t.closeErr = E.Errors(t.closeErr, t.serverScopes.Close())
		if t.configSource != nil {
			t.closeErr = E.Errors(t.closeErr, lifecycle.Uncertain("local configuration source", closeConfigSource(t.configSource)))
		}
		if t.preferredResolver != nil && t.preferredResolver.hosts != nil {
			t.closeErr = E.Errors(t.closeErr, t.preferredResolver.hosts.Close())
		}
	})
	return t.closeErr
}
