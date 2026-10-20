package dialer

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type resolverTestManager struct {
	adapter.DNSTransportManager
	transport adapter.DNSTransport
	lookups   int
}

func (m *resolverTestManager) Transport(tag string) (adapter.DNSTransport, bool) {
	m.lookups++
	return m.transport, tag == "bootstrap"
}

func (m *resolverTestManager) Transports() []adapter.DNSTransport {
	return []adapter.DNSTransport{m.transport}
}

func (m *resolverTestManager) Default() adapter.DNSTransport { return m.transport }

type resolverTestNetwork struct {
	adapter.NetworkManager
	options adapter.NetworkOptions
}

func (m resolverTestNetwork) DefaultOptions() adapter.NetworkOptions { return m.options }

func (m resolverTestNetwork) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}

func (m resolverTestNetwork) AutoDetectInterface() bool                { return false }
func (m resolverTestNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }

type resolverTestOutboundManager struct{ adapter.OutboundManager }

func TestDomainResolverRulesQueryOptions(t *testing.T) {
	ttl := uint32(17)
	subnet := netip.MustParsePrefix("192.0.2.0/24")
	resolver := &option.DomainResolveOptions{
		Mode:         option.DomainResolverModeRules,
		Strategy:     option.DomainStrategy(C.DomainStrategyPreferIPv4),
		Timeout:      badoption.Duration(2 * time.Second),
		DisableCache: true, DisableOptimisticCache: true, RewriteTTL: &ttl,
		ClientSubnet: (*badoption.Prefixable)(&subnet),
	}
	options, err := NewDNSQueryOptions(context.Background(), resolver, true)
	require.NoError(t, err)
	require.True(t, options.UseRules)
	require.Nil(t, options.Transport)
	require.Equal(t, C.DomainStrategyPreferIPv4, options.Strategy)
	require.Equal(t, 2*time.Second, options.Timeout)
	require.True(t, options.DisableCache)
	require.True(t, options.DisableOptimisticCache)
	require.Equal(t, &ttl, options.RewriteTTL)
	require.Equal(t, netip.MustParsePrefix("192.0.2.0/24"), options.ClientSubnet)

	// Explicit transport overrides a rules-mode default. Ordinary one-server
	// defaults still pick that transport rather than silently executing rules.
	transport := &struct{ adapter.DNSTransport }{}
	manager := &resolverTestManager{transport: transport}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.NetworkManager](ctx, resolverTestNetwork{options: adapter.NetworkOptions{DomainResolveOptions: options}})
	inherited, err := NewDNSQueryOptions(ctx, nil, true)
	require.NoError(t, err)
	require.Equal(t, options, inherited)
	direct, err := NewDNSQueryOptions(ctx, &option.DomainResolveOptions{Server: "bootstrap"}, true)
	require.NoError(t, err)
	require.False(t, direct.UseRules)
	require.Same(t, transport, direct.Transport)
	ctx = service.ContextWith[adapter.NetworkManager](ctx, resolverTestNetwork{})
	single, err := NewDNSQueryOptions(ctx, nil, true)
	require.NoError(t, err)
	require.Same(t, transport, single.Transport)
	_, err = NewDNSQueryOptions(ctx, &option.DomainResolveOptions{Server: "missing"}, true)
	require.ErrorContains(t, err, "domain resolver not found")
	for _, invalid := range []*option.DomainResolveOptions{
		{Mode: "invalid"}, {Mode: option.DomainResolverModeRules, Server: "bootstrap"},
	} {
		_, err = NewDNSQueryOptions(context.Background(), invalid, true)
		require.Error(t, err)
	}
}

func TestDomainResolverRulesWrapsDetourAndRejectsDNSBootstrap(t *testing.T) {
	rules := &option.DomainResolveOptions{Mode: option.DomainResolverModeRules}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), resolverTestOutboundManager{})
	for _, detour := range []string{"", "node-exit"} {
		dialerOptions := option.DialerOptions{Detour: detour, DomainResolver: rules}
		resolved, err := NewWithOptions(Options{Context: ctx, Options: dialerOptions, RemoteIsDomain: true, NewDialer: true})
		require.NoError(t, err)
		require.True(t, resolved.(ResolveDialer).QueryOptions().UseRules)
		for _, remoteIsDomain := range []bool{true, false} {
			_, err = NewWithOptions(Options{Context: ctx, Options: dialerOptions, RemoteIsDomain: remoteIsDomain, DirectResolver: true})
			require.ErrorContains(t, err, "DNS server domain_resolver cannot use rules mode")
		}
	}
	// Direct DNS bootstrap never inherits route.default_domain_resolver.
	ctx = service.ContextWith[adapter.NetworkManager](context.Background(), resolverTestNetwork{options: adapter.NetworkOptions{DomainResolveOptions: adapter.DNSQueryOptions{UseRules: true}}})
	_, err := NewWithOptions(Options{Context: ctx, RemoteIsDomain: true, DirectResolver: true})
	require.ErrorContains(t, err, "missing domain resolver")
}

type resolverTestRouter struct {
	adapter.DNSRouter
	options adapter.DNSQueryOptions
	domain  string
}

func (r *resolverTestRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.domain, r.options = domain, options
	return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
}

type resolverTestDialer struct{ destination M.Socksaddr }

func (d *resolverTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.destination = destination
	return nil, nil
}

func (d *resolverTestDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	panic("unused")
}

func TestDomainResolverRulesLazyInitializationPreservesMode(t *testing.T) {
	router := &resolverTestRouter{}
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), router)
	base := &resolverTestDialer{}
	resolved := NewResolveDialer(ctx, base, false, "", adapter.DNSQueryOptions{UseRules: true, Strategy: C.DomainStrategyPreferIPv4, Timeout: 2 * time.Second}, 0)
	_, err := resolved.DialContext(ctx, "tcp", M.ParseSocksaddr("node.example:443"))
	require.NoError(t, err)
	require.Equal(t, "node.example", router.domain)
	require.True(t, router.options.UseRules)
	require.Nil(t, router.options.Transport)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), base.destination.Addr)
}

// HasResolverPolicy models the policy inventory exposed after DNS initialization.
type resolverPolicyTestRouter struct {
	resolverTestRouter
	policies map[string]bool
}

func (r *resolverPolicyTestRouter) HasResolverPolicy(policy string) bool {
	return r.policies[policy]
}

func TestInheritedDomainResolverPolicy(t *testing.T) {
	policy := "bootstrap-policy"
	transport := &struct{ adapter.DNSTransport }{}
	manager := &resolverTestManager{transport: transport}
	router := &resolverPolicyTestRouter{policies: map[string]bool{policy: true}}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.DNSRouter](ctx, router)
	defaults := adapter.DNSQueryOptions{UseRules: true, Policy: policy, Timeout: time.Second}
	ctx = service.ContextWith[adapter.NetworkManager](ctx, resolverTestNetwork{options: adapter.NetworkOptions{DomainResolveOptions: defaults}})
	inherited, err := NewDNSQueryOptions(ctx, nil, true)
	require.NoError(t, err)
	require.Equal(t, defaults, inherited)
	require.Zero(t, manager.lookups)

	// The inherited policy survives lazy resolver initialization and reaches Lookup.
	base := &resolverTestDialer{}
	resolved := NewResolveDialer(ctx, base, false, "", inherited, 0)
	_, err = resolved.DialContext(ctx, "tcp", M.ParseSocksaddr("node.example:443"))
	require.NoError(t, err)
	require.Equal(t, policy, router.options.Policy)
	require.True(t, router.options.UseRules)

	// Unknown inherited policies fail at dialer construction, without fallback.
	delete(router.policies, policy)
	_, err = NewDNSQueryOptions(ctx, nil, true)
	require.ErrorContains(t, err, "unknown DNS resolver policy: "+policy)
	_, err = NewDNSQueryOptions(ctx, &option.DomainResolveOptions{Mode: option.DomainResolverModeRules, Policy: &policy}, true)
	require.ErrorContains(t, err, "unknown DNS resolver policy: "+policy)

	// An explicit transport bypasses even an unknown default policy.
	direct, err := NewDNSQueryOptions(ctx, &option.DomainResolveOptions{Server: "bootstrap"}, true)
	require.NoError(t, err)
	require.Same(t, transport, direct.Transport)
	require.False(t, direct.UseRules)
	require.Empty(t, direct.Policy)

	// Ordinary rule evaluation has no named-policy dependency.
	defaults.Policy = ""
	ctx = service.ContextWith[adapter.NetworkManager](ctx, resolverTestNetwork{options: adapter.NetworkOptions{DomainResolveOptions: defaults}})
	ordinary, err := NewDNSQueryOptions(ctx, nil, true)
	require.NoError(t, err)
	require.Equal(t, defaults, ordinary)

	// A missing router cannot silently accept an inherited named policy.
	defaults.Policy = policy
	missing := service.ContextWith[adapter.NetworkManager](context.Background(), resolverTestNetwork{options: adapter.NetworkOptions{DomainResolveOptions: defaults}})
	_, err = NewDNSQueryOptions(missing, nil, true)
	require.ErrorContains(t, err, "unknown DNS resolver policy: "+policy)
}
