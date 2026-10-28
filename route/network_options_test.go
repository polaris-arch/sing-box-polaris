package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	D "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestNetworkOptionsProjectionAndOwnership(t *testing.T) {
	var options option.RouteOptions
	require.NoError(t, json.Unmarshal([]byte(`{"default_domain_resolver":{"mode":"rules","policy":"candidate-only","timeout":"2s","strategy":"prefer_ipv6","disable_cache":true,"disable_optimistic_cache":true,"rewrite_ttl":7,"client_subnet":"192.0.2.0/24"},"default_network_type":["wifi"],"default_fallback_network_type":["cellular"],"default_fallback_delay":"3s"}`), &options))
	got, err := BuildNetworkOptions(options)
	require.NoError(t, err) // Existence is validated only after DNS initialization.
	require.True(t, got.DomainResolveOptions.UseRules)
	require.Equal(t, "candidate-only", got.DomainResolveOptions.Policy)
	require.Equal(t, 2*time.Second, got.DomainResolveOptions.Timeout)
	require.Equal(t, C.DomainStrategyPreferIPv6, got.DomainResolveOptions.Strategy)
	require.True(t, got.DomainResolveOptions.DisableCache)
	require.True(t, got.DomainResolveOptions.DisableOptimisticCache)
	require.Equal(t, "192.0.2.0/24", got.DomainResolveOptions.ClientSubnet.String())
	require.Equal(t, 3*time.Second, got.FallbackDelay)
	require.Equal(t, options.DefaultNetworkType[0].Build(), got.NetworkType[0])
	require.Equal(t, options.DefaultFallbackNetworkType[0].Build(), got.FallbackNetworkType[0])
	*options.DefaultDomainResolver.RewriteTTL = 99
	options.DefaultNetworkType[0] = options.DefaultFallbackNetworkType[0]
	require.Equal(t, uint32(7), *got.DomainResolveOptions.RewriteTTL)
	require.NotEqual(t, options.DefaultNetworkType[0].Build(), got.NetworkType[0])
	server, err := BuildNetworkOptions(option.RouteOptions{DefaultDomainResolver: &option.DomainResolveOptions{Server: "resolver"}})
	require.NoError(t, err)
	require.Equal(t, "resolver", server.DomainResolver)
	_, err = BuildNetworkOptions(option.RouteOptions{})
	require.NoError(t, err)
	_, err = BuildNetworkOptions(option.RouteOptions{DefaultDomainResolver: &option.DomainResolveOptions{Mode: "invalid"}})
	require.ErrorContains(t, err, "unknown domain_resolver.mode")
	if C.IsLinux {
		projected, err := BuildNetworkOptions(option.RouteOptions{DefaultInterface: "test0", DefaultMark: 19})
		require.NoError(t, err)
		require.Equal(t, "test0", projected.BindInterface)
		require.Equal(t, uint32(19), projected.RoutingMark)
	}
}

type optionsTestOwner struct {
	adapter.NetworkManager
	starts, initializes int
}

func (o *optionsTestOwner) Start(adapter.StartStage, *adapter.Scope) error { o.starts++; return nil }
func (o *optionsTestOwner) Initialize([]adapter.RuleSet)                   { o.initializes++ }
func (*optionsTestOwner) NetworkEnvironment() uint64                       { return 37 }

type optionsTestDNS struct {
	adapter.DNSRouter
	adapter.DNSRuleSetUpdateValidator
}

func TestNetworkOptionsViewCopiesAndBorrows(t *testing.T) {
	owner := &optionsTestOwner{}
	strategy := C.NetworkStrategy(0)
	ttl := uint32(5)
	defaults := adapter.NetworkOptions{NetworkStrategy: &strategy, NetworkType: []C.InterfaceType{0}, FallbackNetworkType: []C.InterfaceType{1}, DomainResolveOptions: adapter.DNSQueryOptions{RewriteTTL: &ttl}}
	view, err := NewNetworkOptionsView(owner, defaults)
	require.NoError(t, err)
	strategy = C.NetworkStrategy(1)
	ttl = 99
	defaults.NetworkType[0] = 2
	first := view.DefaultOptions()
	require.Equal(t, C.NetworkStrategy(0), *first.NetworkStrategy)
	require.Equal(t, uint32(5), *first.DomainResolveOptions.RewriteTTL)
	*first.NetworkStrategy = 3
	*first.DomainResolveOptions.RewriteTTL = 77
	first.NetworkType[0] = 4
	first.FallbackNetworkType[0] = 4
	second := view.DefaultOptions()
	require.Equal(t, C.NetworkStrategy(0), *second.NetworkStrategy)
	require.Equal(t, uint32(5), *second.DomainResolveOptions.RewriteTTL)
	require.Equal(t, C.InterfaceType(0), second.NetworkType[0])
	require.Equal(t, C.InterfaceType(1), second.FallbackNetworkType[0])
	require.Equal(t, uint64(37), view.NetworkEnvironment())
	view.Initialize(nil)
	require.Equal(t, 1, owner.initializes)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("test"))
	for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart, adapter.StartStatePostStart, adapter.StartStateStarted} {
		require.ErrorContains(t, view.Start(stage, scope), "non-owning")
	}
	require.Zero(t, owner.starts)
	require.NoError(t, scope.Context().Err())
	require.NoError(t, scope.Close())
	_, err = NewNetworkOptionsView(nil, defaults)
	require.Error(t, err)
}

func TestNetworkOptionsContextIsolationAndValidatorRebinding(t *testing.T) {
	owner := &optionsTestOwner{}
	parent := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.NetworkManager](parent, owner)
	oldDNS := &optionsTestDNS{}
	service.MustRegister[adapter.DNSRouter](parent, oldDNS)
	service.MustRegister[adapter.DNSRuleSetUpdateValidator](parent, oldDNS)
	child, err := ContextWithNetworkOptions(parent, owner, option.RouteOptions{})
	require.NoError(t, err)
	sibling, err := ContextWithNetworkOptions(parent, owner, option.RouteOptions{})
	require.NoError(t, err)
	require.Same(t, owner, service.FromContext[adapter.NetworkManager](parent))
	require.NotSame(t, service.FromContext[adapter.NetworkManager](child), service.FromContext[adapter.NetworkManager](sibling))
	candidateDNS := &optionsTestDNS{}
	service.MustRegister[adapter.DNSRouter](child, candidateDNS)
	// Both bindings are mandatory: the network helper deliberately replaces neither.
	require.Same(t, oldDNS, service.FromContext[adapter.DNSRuleSetUpdateValidator](child))
	service.MustRegister[adapter.DNSRuleSetUpdateValidator](child, candidateDNS)
	require.Same(t, candidateDNS, service.FromContext[adapter.DNSRouter](child))
	require.Same(t, candidateDNS, service.FromContext[adapter.DNSRuleSetUpdateValidator](child))
	for _, untouched := range []context.Context{parent, sibling} {
		require.Same(t, oldDNS, service.FromContext[adapter.DNSRouter](untouched))
		require.Same(t, oldDNS, service.FromContext[adapter.DNSRuleSetUpdateValidator](untouched))
	}
	_, err = ContextWithNetworkOptions(parent, owner, option.RouteOptions{DefaultDomainResolver: &option.DomainResolveOptions{Mode: "invalid"}})
	require.Error(t, err)
	require.Same(t, owner, service.FromContext[adapter.NetworkManager](parent))
	bare := context.Background()
	isolated, err := ContextWithNetworkOptions(bare, owner, option.RouteOptions{})
	require.NoError(t, err)
	require.Nil(t, service.FromContext[adapter.NetworkManager](bare))
	require.NotNil(t, service.FromContext[adapter.NetworkManager](isolated))
}

func (*optionsTestDNS) HasResolverPolicy(policy string) bool { return policy == "candidate-only" }

type optionsFakeIPOwner struct{ adapter.CacheFile }

func (*optionsFakeIPOwner) StoreFakeIP() bool { return true }

func TestNetworkOptionsViewFeedsActualDialerDefaults(t *testing.T) {
	owner := &optionsTestOwner{}
	parent := service.ContextWithDefaultRegistry(context.Background())
	fakeIP := &optionsFakeIPOwner{}
	service.MustRegister[adapter.CacheFile](parent, fakeIP)
	policy := "candidate-only"
	child, err := ContextWithNetworkOptions(parent, owner, option.RouteOptions{DefaultDomainResolver: &option.DomainResolveOptions{Mode: option.DomainResolverModeRules, Policy: &policy}})
	require.NoError(t, err) // Construction does not perform premature policy lookup.
	_, err = dialer.NewDNSQueryOptions(child, nil, true)
	require.ErrorContains(t, err, "unknown DNS resolver policy")
	candidateDNS := &optionsTestDNS{}
	service.MustRegister[adapter.DNSRouter](child, candidateDNS)
	service.MustRegister[adapter.DNSRuleSetUpdateValidator](child, candidateDNS)
	got, err := dialer.NewDNSQueryOptions(child, nil, true)
	require.NoError(t, err)
	require.True(t, got.UseRules)
	require.Equal(t, policy, got.Policy)
	explicit := &option.DomainResolveOptions{Mode: option.DomainResolverModeRules}
	got, err = dialer.NewDNSQueryOptions(child, explicit, true)
	require.NoError(t, err)
	require.Empty(t, got.Policy)
	require.Same(t, fakeIP, service.FromContext[adapter.CacheFile](child))
	require.Same(t, fakeIP, service.FromContext[adapter.CacheFile](parent))
	require.True(t, service.FromContext[adapter.CacheFile](child).StoreFakeIP())
}

func TestNetworkOptionsStrategyOwnershipAndValidation(t *testing.T) {
	strategy := option.NetworkStrategy(0)
	_, err := BuildNetworkOptions(option.RouteOptions{DefaultNetworkStrategy: &strategy})
	require.ErrorContains(t, err, "auto_detect_interface")
	if !(C.IsLinux || C.IsDarwin || C.IsWindows) {
		return
	}
	options := option.RouteOptions{AutoDetectInterface: true, DefaultNetworkStrategy: &strategy}
	got, err := BuildNetworkOptions(options)
	require.NoError(t, err)
	strategy = option.NetworkStrategy(1)
	require.Equal(t, C.NetworkStrategy(0), *got.NetworkStrategy)
	options.DefaultInterface = "test0"
	_, err = BuildNetworkOptions(options)
	require.ErrorContains(t, err, "conflict with `default_interface`")
	manager := &NetworkManager{defaultOptions: got}
	borrowed := manager.DefaultOptions()
	*borrowed.NetworkStrategy = 2
	require.Equal(t, C.NetworkStrategy(0), *manager.DefaultOptions().NetworkStrategy)
}

type optionsNamedTransport struct {
	adapter.DNSTransport
	tag string
}

func (t *optionsNamedTransport) Tag() string { return t.tag }

type optionsTransportManager struct {
	adapter.DNSTransportManager
	transport adapter.DNSTransport
}

func (m *optionsTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	return m.transport, tag == "resolver"
}

func TestNetworkOptionsActualDNSRouterContexts(t *testing.T) {
	parent := service.ContextWithDefaultRegistry(context.Background())
	owner := &optionsTestOwner{}
	contexts := make([]context.Context, 2)
	transports := []*optionsNamedTransport{{tag: "old-transport"}, {tag: "new-transport"}}
	for i, policy := range []string{"old-only", "new-only"} {
		var options option.RouteOptions
		require.NoError(t, json.Unmarshal([]byte(`{"default_domain_resolver":{"mode":"rules","policy":"`+policy+`","timeout":"2s","strategy":"prefer_ipv6","disable_cache":true,"disable_optimistic_cache":true,"rewrite_ttl":7,"client_subnet":"192.0.2.0/24"}}`), &options))
		ctx, err := ContextWithNetworkOptions(parent, owner, options)
		require.NoError(t, err)
		service.MustRegister[adapter.DNSTransportManager](ctx, &optionsTransportManager{transport: transports[i]})
		router, err := D.NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), option.DNSOptions{}, D.RouterClientDependencies{})
		require.NoError(t, err)
		service.MustRegister[adapter.DNSRouter](ctx, router)
		service.MustRegister[adapter.DNSRuleSetUpdateValidator](ctx, router)
		_, err = dialer.NewDNSQueryOptions(ctx, nil, true)
		require.ErrorContains(t, err, "unknown DNS resolver policy")
		failure := option.DNSRCode(2)
		rules := []option.DNSRule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{ResolverPolicy: &policy},
			DNSRuleAction:     option.DNSRuleAction{Action: C.RuleActionTypeRespond, RespondOptions: option.DNSRespondActionOptions{Mode: "fallback", FallbackRcode: &failure}},
		}}}
		require.NoError(t, router.Initialize(rules))
		got, err := dialer.NewDNSQueryOptions(ctx, nil, true)
		require.NoError(t, err)
		require.True(t, got.UseRules)
		require.Equal(t, policy, got.Policy)
		require.Equal(t, 2*time.Second, got.Timeout)
		require.Equal(t, C.DomainStrategyPreferIPv6, got.Strategy)
		require.True(t, got.DisableCache)
		require.True(t, got.DisableOptimisticCache)
		require.Equal(t, uint32(7), *got.RewriteTTL)
		require.Equal(t, "192.0.2.0/24", got.ClientSubnet.String())
		require.Nil(t, got.Transport)
		contexts[i] = ctx
		// Server mode uses this context's distinct manager, including inherited
		// default query fields. The original rules-default context remains intact.
		serverOptions := options
		resolver := *options.DefaultDomainResolver
		resolver.Mode, resolver.Policy, resolver.Server = "", nil, "resolver"
		serverOptions.DefaultDomainResolver = &resolver
		serverCtx, err := ContextWithNetworkOptions(ctx, owner, serverOptions)
		require.NoError(t, err)
		serverGot, err := dialer.NewDNSQueryOptions(serverCtx, nil, true)
		require.NoError(t, err)
		require.Same(t, transports[i], serverGot.Transport)
		got.UseRules, got.Policy, got.Transport = false, "", transports[i]
		require.Equal(t, got, serverGot)
	}
	for i, ctx := range contexts {
		other := []string{"new-only", "old-only"}[i]
		_, err := dialer.NewDNSQueryOptions(ctx, &option.DomainResolveOptions{Mode: option.DomainResolverModeRules, Policy: &other}, true)
		require.ErrorContains(t, err, "unknown DNS resolver policy")
		own, err := dialer.NewDNSQueryOptions(ctx, nil, true)
		require.NoError(t, err)
		require.Equal(t, []string{"old-only", "new-only"}[i], own.Policy)
	}
	require.Nil(t, service.FromContext[adapter.DNSRouter](parent))
	require.Nil(t, service.FromContext[adapter.DNSTransportManager](parent))
}
