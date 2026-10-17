package rule

import (
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/miekg/dns"
)

// DNSResponseClassItem deliberately does not use DNSResponseAddresses: hints,
// additional records and answers of the other family are not a current-qtype HIT.
type DNSResponseClassItem struct {
	class  string
	reject []netip.Prefix
}

func NewDNSResponseClassItem(class string, reject []*badoption.Prefixable) (*DNSResponseClassItem, error) {
	if class != "hit" && class != "empty" {
		return nil, E.New("unknown response_class: ", class)
	}
	item := &DNSResponseClassItem{class: class}
	for _, prefix := range reject {
		if prefix == nil || !netip.Prefix(*prefix).IsValid() {
			return nil, E.New("invalid response_reject_ip_cidr")
		}
		item.reject = append(item.reject, netip.Prefix(*prefix))
	}
	return item, nil
}

func (r *DNSResponseClassItem) Match(metadata *adapter.InboundContext) bool {
	response := metadata.DNSResponse
	qtype := metadata.QueryType
	if response == nil || !response.Response || response.Truncated {
		return false
	}
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return false
	}
	hit, poisoned := false, false
	for _, record := range response.Answer {
		if record == nil {
			return false
		}
		header := record.Header()
		if header.Class != dns.ClassINET {
			continue
		}
		if header.Rrtype == qtype {
			hit = true
		}
		var address netip.Addr
		switch answer := record.(type) {
		case *dns.A:
			raw := answer.A.To4()
			if raw == nil {
				return false
			}
			address, _ = netip.AddrFromSlice(raw)
			if qtype == dns.TypeA {
				hit = true
			}
		case *dns.AAAA:
			if len(answer.AAAA) != 16 {
				return false
			}
			address, _ = netip.AddrFromSlice(answer.AAAA)
			if qtype == dns.TypeAAAA {
				hit = true
			}
		}
		if address.IsValid() {
			for _, prefix := range r.reject {
				if prefix.Contains(address) {
					poisoned = true
					break
				}
			}
		}
	}
	// Preserve the old classifier: NXDOMAIN wins over extraneous Answer RRs;
	// decoy rejection applies to HIT packets, not EMPTY classification.
	if response.Rcode == dns.RcodeNameError || !hit {
		return r.class == "empty"
	}
	return r.class == "hit" && !poisoned
}

func (r *DNSResponseClassItem) String() string { return "response_class=" + r.class }

type dnsResolverPolicyItem struct{ policy string }

func (r *dnsResolverPolicyItem) Match(metadata *adapter.InboundContext) bool {
	return metadata.DNSResolverPolicy == r.policy
}
func (r *dnsResolverPolicyItem) String() string { return "resolver_policy=" + r.policy }

// Validation is deliberately scoped: generic DNS Groups keep their old race,
// deadline and response matching behavior when all new fields are omitted.
func validateDNSPolicyRule(options option.DefaultDNSRule) error {
	policy := options.ResolverPolicy
	response := options.RespondOptions
	if policy != nil && *policy == "" {
		return E.New("empty resolver_policy")
	}
	if policy == nil && (options.ResponseClass != "" || len(options.ResponseRejectIPCIDR) > 0 || response.Mode == "defer" || response.Mode == "fallback" || response.FallbackRcode != nil) {
		return E.New("response policy fields require resolver_policy")
	}
	if options.ResponseClass != "" {
		if options.ResponseClass != "hit" && options.ResponseClass != "empty" {
			return E.New("unknown response_class: ", options.ResponseClass)
		}
		if !options.MatchResponse.IsEnabled() {
			return E.New("response_class requires match_response")
		}
	}
	if len(options.ResponseRejectIPCIDR) > 0 && options.ResponseClass != "hit" {
		return E.New("response_reject_ip_cidr requires response_class=hit")
	}
	switch response.Mode {
	case "", "immediate":
		if response.FallbackRcode != nil {
			return E.New("fallback_rcode requires respond mode=fallback")
		}
	case "defer":
		if options.Action != "respond" || options.ResponseClass != "empty" || !options.Race || response.FallbackRcode != nil {
			return E.New("defer requires a racing EMPTY respond")
		}
	case "fallback":
		if options.Action != "respond" || options.MatchResponse.IsEnabled() || options.Race || options.ResponseClass != "" || response.FallbackRcode == nil {
			return E.New("fallback requires unbound terminal respond with explicit fallback_rcode")
		}
		if int(*response.FallbackRcode) != dns.RcodeServerFailure {
			return E.New("policy fallback_rcode must be SERVFAIL")
		}
	default:
		return E.New("unknown respond mode: ", response.Mode)
	}
	return nil
}
