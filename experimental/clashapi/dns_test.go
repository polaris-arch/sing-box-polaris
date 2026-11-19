package clashapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type managementDNSTestRouter struct {
	adapter.DNSRouter
	lookup   func(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error)
	exchange func(*dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error)
}

func (r managementDNSTestRouter) Lookup(ctx context.Context, name string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.lookup(ctx, name, options)
}

func (r managementDNSTestRouter) Exchange(_ context.Context, msg *dns.Msg, options adapter.DNSQueryOptions) (*dns.Msg, error) {
	return r.exchange(msg, options)
}

func TestManagementDNSLookupKeepsAuthenticationAndQuerySemantics(t *testing.T) {
	requestContext, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	lookups, exchanges := 0, 0
	wantedDeadline, _ := requestContext.Deadline()
	router := managementDNSTestRouter{
		lookup: func(ctx context.Context, name string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
			lookups++
			require.Equal(t, adapter.DNSQueryOptions{UseRules: true}, options)
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			require.Equal(t, wantedDeadline, deadline)
			if name == "overflow.example" {
				return make([]netip.Addr, 65), nil
			}
			require.Equal(t, "example.org", name)
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700::1111"), netip.MustParseAddr("10.0.0.1")}, nil
		},
		exchange: func(msg *dns.Msg, options adapter.DNSQueryOptions) (*dns.Msg, error) {
			exchanges++
			require.Equal(t, adapter.DNSQueryOptions{}, options)
			require.Equal(t, dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, msg.Question[0])
			response := new(dns.Msg).SetReply(msg)
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(198, 18, 0, 1)}}
			return response, nil
		},
	}
	ctx := service.ContextWith[adapter.DNSRouter](t.Context(), router)
	ctx = service.ContextWithPtr(ctx, new(trafficcontrol.Manager))
	ctx = service.ContextWithPtr(ctx, new(urltest.HistoryStorage))
	ctx = service.ContextWithPtr(ctx, new(clashmode.Manager))
	server, err := NewServer(ctx, log.NewNOPFactory(), option.ClashAPIOptions{Secret: "test-secret"})
	require.NoError(t, err)

	request := func(target string, authorized bool) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(requestContext, http.MethodGet, target, nil)
		if authorized {
			req.Header.Set("Authorization", "Bearer test-secret")
		}
		response := httptest.NewRecorder()
		server.(*Server).httpServer.Handler.ServeHTTP(response, req)
		return response
	}
	require.Equal(t, http.StatusUnauthorized, request("/dns/lookup?name=example.org", false).Code)
	require.Equal(t, http.StatusBadRequest, request("/dns/lookup?name=example.org&server=other", true).Code)
	require.Equal(t, http.StatusBadRequest, request("/dns/lookup?name="+strings.Repeat("a", 1000), true).Code)
	require.Zero(t, lookups)
	result := request("/dns/lookup?name=example.org", true)
	require.Equal(t, http.StatusOK, result.Code)
	require.JSONEq(t, `{"version":1,"addresses":["8.8.8.8","2606:4700::1111","10.0.0.1"]}`, result.Body.String())
	require.Equal(t, http.StatusBadGateway, request("/dns/lookup?name=overflow.example", true).Code)
	legacy := request("/dns/query?name=example.org", true)
	require.Equal(t, http.StatusOK, legacy.Code)
	require.Contains(t, legacy.Body.String(), "198.18.0.1")
	require.Equal(t, 2, lookups)
	require.Equal(t, 1, exchanges)
}
