package naive

import (
	"context"
	"os"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type callbackTransport struct {
	adapter.DNSTransport
	tag, scenario string
	calls         atomic.Int32
}

func (t *callbackTransport) Type() string { return "test" }
func (t *callbackTransport) Tag() string  { return t.tag }
func (t *callbackTransport) Exchange(_ context.Context, request *mDNS.Msg) (*mDNS.Msg, error) {
	t.calls.Add(1)
	response := dns.FixedResponseStatus(request, mDNS.RcodeSuccess)
	text := "node.native.test. 60 IN HTTPS 1 . alpn=h2 ipv4hint=203.0.113.9"
	if t.scenario == "missing-rtype" {
		text = "node.native.test. 60 IN A 192.0.2.1"
	}
	rr, err := mDNS.NewRR(text)
	if err != nil {
		return nil, err
	}
	response.Answer = []mDNS.RR{rr}
	if t.scenario == "poison" {
		rr, err = mDNS.NewRR("node.native.test. 60 IN A 8.7.198.45")
		if err != nil {
			return nil, err
		}
		response.Answer = append(response.Answer, rr)
	}
	return response, nil
}

func (t *callbackTransport) ExchangeAsync(ctx context.Context, request *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.Exchange(ctx, request)) }()
}

type callbackTransports struct {
	adapter.DNSTransportManager
	entries map[string]adapter.DNSTransport
}

func (t *callbackTransports) Transport(tag string) (adapter.DNSTransport, bool) {
	v, ok := t.entries[tag]
	return v, ok
}

func TestNaiveCallbackUsesActualNativePolicyForHTTPS(t *testing.T) {
	for _, platform := range []string{"linux", "android", "ios"} {
		for _, scenario := range []string{"https-hit", "missing-rtype", "poison"} {
			t.Run(platform+"/"+scenario, func(t *testing.T) {
				data, err := os.ReadFile("../../dns/testdata/node-policy/naive-" + platform + ".json")
				require.NoError(t, err)
				var fixture struct {
					DNS struct {
						Rules []option.DNSRule `json:"rules"`
					} `json:"dns"`
					Outbounds []struct {
						Server   string                       `json:"server"`
						Resolver *option.DomainResolveOptions `json:"domain_resolver"`
					} `json:"outbounds"`
				}
				require.NoError(t, json.UnmarshalContext(context.Background(), data, &fixture))
				var rules []option.DNSRule
				manager := &callbackTransports{entries: map[string]adapter.DNSTransport{}}
				var candidates []*callbackTransport
				for _, rule := range fixture.DNS.Rules {
					if rule.Type != C.RuleTypeDefault || rule.DefaultOptions.ResolverPolicy == nil {
						continue
					}
					rules = append(rules, rule)
					if rule.DefaultOptions.Action == C.RuleActionTypeEvaluate {
						transport := &callbackTransport{tag: rule.DefaultOptions.EvaluateOptions.Server, scenario: scenario}
						manager.entries[transport.tag] = transport
						candidates = append(candidates, transport)
					}
				}
				ordinary := &callbackTransport{tag: "ordinary", scenario: "https-hit"}
				manager.entries[ordinary.tag] = ordinary
				rules = append(rules, option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: "ordinary"}}}})
				ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
				factory := log.NewNOPFactory()
				router, err := dns.NewRouter(ctx, factory, option.DNSOptions{})
				require.NoError(t, err)
				require.NoError(t, router.Initialize(rules))
				scope := adapter.NewScope(ctx, factory.Logger())
				t.Cleanup(func() { require.NoError(t, scope.Close()) })
				require.NoError(t, router.Start(adapter.StartStateStart, scope))
				ctx = service.ContextWith[adapter.DNSRouter](ctx, router)
				var resolver *option.DomainResolveOptions
				for _, outbound := range fixture.Outbounds {
					if outbound.Server == "node.native.test" {
						resolver = outbound.Resolver
					}
				}
				require.NotNil(t, resolver)
				options, err := dialer.NewDNSQueryOptions(ctx, resolver, true)
				require.NoError(t, err)
				callback := newDNSResolver(router, options, factory.Logger())
				request := &mDNS.Msg{Question: []mDNS.Question{{Name: "node.native.test.", Qtype: mDNS.TypeHTTPS, Qclass: mDNS.ClassINET}}}
				response := callback(ctx, request)
				if scenario == "poison" {
					require.Equal(t, mDNS.RcodeServerFailure, response.Rcode)
				} else {
					require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
					require.Len(t, response.Answer, 1)
				}
				if scenario == "https-hit" {
					require.Equal(t, uint16(mDNS.TypeHTTPS), response.Answer[0].Header().Rrtype)
				}
				if scenario == "missing-rtype" {
					require.Equal(t, uint16(mDNS.TypeA), response.Answer[0].Header().Rrtype, "original EMPTY response is preserved")
				}
				calls := int32(0)
				for _, transport := range candidates {
					calls += transport.calls.Load()
				}
				require.Positive(t, calls)
				require.Zero(t, ordinary.calls.Load())
				callback(ctx, request)
				again := int32(0)
				for _, transport := range candidates {
					again += transport.calls.Load()
				}
				if scenario == "poison" {
					require.Greater(t, again, calls)
				} else {
					require.Equal(t, calls, again, "final policy cache is retained")
				}
			})
		}
	}
}
