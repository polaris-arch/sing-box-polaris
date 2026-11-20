package openconnect

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
)

func fixtureEndpointDNS(t *testing.T) *DNSTransport {
	t.Helper()
	transport, err := NewDNSTransport(context.Background(), log.NewNOPFactory().Logger(), "dns", option.OpenConnectDNSServerOptions{
		Endpoint: "endpoint", AcceptDefaultResolvers: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return transport.(*DNSTransport)
}

type endpointDNSIdleResolver struct {
	adapter.DNSTransport
	keep       atomic.Bool
	idleCalls  atomic.Int32
	resetCalls atomic.Int32
	closed     atomic.Int32
	active     atomic.Int32
	access     sync.Mutex
	callback   func(*mDNS.Msg, error)
}

func (r *endpointDNSIdleResolver) Start(_ adapter.StartStage, scope *adapter.Scope) error {
	scope.Add(func() error { r.closed.Add(1); return nil })
	return nil
}

func (r *endpointDNSIdleResolver) Reset()                           { r.resetCalls.Add(1) }
func (r *endpointDNSIdleResolver) SetKeepIdleConnections(keep bool) { r.keep.Store(keep) }
func (r *endpointDNSIdleResolver) CloseIdleConnections()            { r.idleCalls.Add(1) }

func (r *endpointDNSIdleResolver) ExchangeAsync(_ context.Context, _ *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	r.access.Lock()
	r.callback = callback
	r.active.Add(1)
	r.access.Unlock()
}

func (r *endpointDNSIdleResolver) finish() {
	r.access.Lock()
	callback := r.callback
	r.callback = nil
	r.active.Add(-1)
	r.access.Unlock()
	response := new(mDNS.Msg)
	response.Response = true
	callback(response, nil)
}

func TestEndpointDNSIdleControlsPreserveActiveQuery(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	defer dns.dnsLifecycle.Close()
	scope := adapter.NewScope(context.Background(), nil)
	defer scope.Close()
	resolver := new(endpointDNSIdleResolver)
	if err := dns.dnsLifecycle.StartResolver(resolver, scope); err != nil {
		t.Fatal(err)
	}
	if !resolver.keep.Load() {
		t.Fatal("default idle policy must preserve reuse")
	}
	dns.defaultResolvers = []adapter.DNSTransport{resolver}
	var completed atomic.Bool
	message := &mDNS.Msg{Question: []mDNS.Question{{Name: "example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
	dns.ExchangeAsync(context.Background(), message, func(_ *mDNS.Msg, err error) {
		if err != nil {
			t.Errorf("active query failed: %v", err)
		}
		completed.Store(true)
	})
	dns.CloseIdleConnections()
	dns.SetKeepIdleConnections(false)
	if completed.Load() || resolver.active.Load() != 1 || resolver.closed.Load() != 0 || resolver.resetCalls.Load() != 0 {
		t.Fatal("idle control interrupted or reset an active query")
	}
	if resolver.idleCalls.Load() != 1 || resolver.keep.Load() {
		t.Fatal("idle control was not forwarded")
	}
	resolver.finish()
	if !completed.Load() {
		t.Fatal("original query callback was lost")
	}
	dns.SetKeepIdleConnections(true)
	if !resolver.keep.Load() {
		t.Fatal("idle reuse could not be restored")
	}
}

func TestEndpointDNSMetadataIsDetached(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	defer dns.dnsLifecycle.Close()
	original := netip.MustParseAddr("192.0.2.1")
	dns.serverAddresses = []netip.Addr{original}
	dns.searchDomains = []string{"example."}
	addresses := dns.ServerAddresses()
	domains := dns.SearchDomains()
	addresses[0] = netip.Addr{}
	domains[0] = "changed."
	if dns.serverAddresses[0] != original || dns.searchDomains[0] != "example." {
		t.Fatal("metadata escaped mutable owner")
	}
}
