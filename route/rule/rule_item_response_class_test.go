package rule

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func classRR(t *testing.T, value string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(value)
	require.NoError(t, err)
	return rr
}

func TestDNSResponseClassContract(t *testing.T) {
	prefix := badoption.Prefixable(netip.MustParsePrefix("203.0.113.0/24"))
	hit, err := NewDNSResponseClassItem("hit", []*badoption.Prefixable{&prefix})
	require.NoError(t, err)
	empty, err := NewDNSResponseClassItem("empty", nil)
	require.NoError(t, err)
	cases := []struct {
		name       string
		qtype      uint16
		rcode      int
		answer     []string
		extra      []string
		hit, empty bool
	}{
		{"A HIT", dns.TypeA, 0, []string{"node. 60 IN A 192.0.2.1"}, nil, true, false},
		{"AAAA HIT", dns.TypeAAAA, 0, []string{"node. 60 IN AAAA 2001:db8::1"}, nil, true, false},
		{"CNAME multiple A", dns.TypeA, 0, []string{"node. 60 IN CNAME real.", "real. 60 IN A 192.0.2.1", "real. 60 IN A 192.0.2.2"}, nil, true, false},
		{"CNAME alone EMPTY", dns.TypeA, 0, []string{"node. 60 IN CNAME real."}, nil, false, true},
		{"wrong family EMPTY", dns.TypeAAAA, 0, []string{"node. 60 IN A 192.0.2.1"}, nil, false, true},
		{"additional only EMPTY", dns.TypeA, 0, nil, []string{"node. 60 IN A 192.0.2.1"}, false, true},
		{"HTTPS hints EMPTY", dns.TypeA, 0, []string{"node. 60 IN HTTPS 1 . ipv4hint=192.0.2.1"}, nil, false, true},
		{"mixed poison rejects whole HIT", dns.TypeA, 0, []string{"node. 60 IN A 192.0.2.1", "node. 60 IN A 203.0.113.1"}, nil, false, false},
		{"other family poison rejects HIT", dns.TypeAAAA, 0, []string{"node. 60 IN AAAA 2001:db8::1", "node. 60 IN A 203.0.113.1"}, nil, false, false},
		{"NXDOMAIN precedence", dns.TypeA, dns.RcodeNameError, []string{"node. 60 IN A 203.0.113.1"}, nil, false, true},
		{"wrong family decoy remains EMPTY", dns.TypeAAAA, 0, []string{"node. 60 IN A 203.0.113.1"}, nil, false, true},
		{"SERVFAIL is failure", dns.TypeA, dns.RcodeServerFailure, nil, nil, false, false},
		{"REFUSED is failure", dns.TypeA, dns.RcodeRefused, nil, nil, false, false},
		{"TXT actual current type HIT", dns.TypeTXT, 0, []string{"node. 60 IN TXT hello"}, nil, true, false},
		{"HTTPS actual current type HIT", dns.TypeHTTPS, 0, []string{"node. 60 IN HTTPS 1 . ipv4hint=203.0.113.9"}, nil, true, false},
		{"HTTPS missing type EMPTY", dns.TypeHTTPS, 0, []string{"node. 60 IN A 192.0.2.1"}, nil, false, true},
		{"HTTPS whole Answer decoy rejected", dns.TypeHTTPS, 0, []string{"node. 60 IN HTTPS 1 .", "node. 60 IN A 203.0.113.9"}, nil, false, false},
		{"wrong class ignored", dns.TypeA, 0, []string{"node. 60 CH A 192.0.2.1"}, nil, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message := &dns.Msg{Response: true, Rcode: tc.rcode}
			for _, value := range tc.answer {
				message.Answer = append(message.Answer, classRR(t, value))
			}
			for _, value := range tc.extra {
				message.Extra = append(message.Extra, classRR(t, value))
			}
			// The response's returned Question does not control classification.
			message.Question = []dns.Question{{Name: "untrusted.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}
			metadata := &adapter.InboundContext{QueryType: tc.qtype, DNSResponse: message}
			require.Equal(t, tc.hit, hit.Match(metadata))
			require.Equal(t, tc.empty, empty.Match(metadata))
			message.Truncated = true
			require.False(t, hit.Match(metadata))
			require.False(t, empty.Match(metadata))
			message.Truncated = false
			message.Response = false
			require.False(t, hit.Match(metadata))
			require.False(t, empty.Match(metadata))
		})
	}
	malformed := &dns.Msg{Response: true, Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IP{1, 2}}}}
	require.False(t, hit.Match(&adapter.InboundContext{QueryType: dns.TypeA, DNSResponse: malformed}))
	require.False(t, empty.Match(&adapter.InboundContext{QueryType: dns.TypeA, DNSResponse: malformed}))
}

func TestDNSResponsePolicyFieldsRejectInvalidCombinations(t *testing.T) {
	for _, input := range []string{
		`{"match_response":"r","response_class":"hit","action":"respond"}`,
		`{"resolver_policy":"","action":"respond","mode":"fallback","fallback_rcode":"SERVFAIL"}`,
		`{"resolver_policy":"node","response_class":"hit","action":"respond"}`,
		`{"resolver_policy":"node","match_response":"r","response_class":"empty","response_reject_ip_cidr":"203.0.113.0/24","action":"respond","race":true}`,
		`{"resolver_policy":"node","match_response":"r","response_class":"hit","action":"respond","mode":"defer","race":true}`,
		`{"resolver_policy":"node","match_response":"r","action":"respond","mode":"fallback","fallback_rcode":"SERVFAIL"}`,
		`{"resolver_policy":"node","action":"respond","mode":"fallback","fallback_rcode":"NOERROR"}`,
	} {
		var raw option.DNSRule
		err := json.UnmarshalContext(context.Background(), []byte(input), &raw)
		if err == nil {
			_, err = NewDNSRule(context.Background(), log.NewNOPFactory().Logger(), raw, true, false)
		}
		require.Error(t, err, input)
	}
}
