package box

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	mdns "github.com/miekg/dns"
)

// Box.New, the production TCP transport and its bound detour execute the wire
// query. Only the remote DNS peer is an in-memory fixture. The answer identifies
// the destination actually dialed, rather than the candidate's declared digest.
func TestRuntimeDNSOptionsReplaceActualTargetAndRetainOldLease(t *testing.T) {
	// Register before Box/lease cleanup. Only production closes the clients;
	// this fixture subsequently seals and joins its server-side workers.
	wireServer := newRuntimeDNSWireServer(t, nil)
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "resolver.test"), func(o *runtimeTestSocks) error {
		o.dialHook = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			if network != "tcp" {
				t.Errorf("DNS did not use TCP: %s", network)
			}
			return wireServer.dial(ctx, destination.AddrString())
		}
		return nil
	})
	server := &option.RemoteDNSServerOptions{Server: "192.0.2.53", Detour: "a"}
	options.DNS.Servers = []option.DNSServerOptions{{Type: "tcp", Tag: "fixture", Options: server}}
	options.DNS.Final = "fixture"
	runtimeResourceNew(t, f, options)
	f.start(t)
	oldLease, oldView := f.acquire(t)
	oldTransport, ok := oldView.DNSTransportManager().Transport("fixture")
	if !ok {
		t.Fatal("production DNS transport missing")
	}
	query := func(lease adapter.RuntimeLease, transport adapter.DNSTransport, want string) {
		t.Helper()
		message := new(mdns.Msg)
		message.SetQuestion("target.fixture.", mdns.TypeA)
		response, err := transport.Exchange(adapter.ContextWithRuntimeLease(runtimeTestContext(t), lease), message)
		if err != nil {
			t.Fatal(err)
		}
		if len(response.Answer) != 1 || response.Answer[0].(*mdns.A).A.String() != want {
			t.Fatalf("wire query reached the wrong target: %v, want %s", response.Answer, want)
		}
	}
	query(oldLease, oldTransport, "192.0.2.53")
	wireServer.waitProbe(t, "192.0.2.53")
	// A real unrelated publication must reuse the unchanged DNS allocation.
	options.Outbounds[1].Options.(*option.SOCKSOutboundOptions).ServerPort++
	_, unchanged := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), unchanged))
	stableLease, stableView := f.acquire(t)
	stableTransport, _ := stableView.DNSTransportManager().Transport("fixture")
	if stableTransport != oldTransport || stableView.componentIDs["dns-transport:fixture"] != oldView.componentIDs["dns-transport:fixture"] {
		t.Fatal("unchanged DNS transport lost its exact allocation")
	}
	query(stableLease, stableTransport, "192.0.2.53")
	query(stableLease, stableTransport, "192.0.2.53")
	server.Server = "192.0.2.54"
	_, change := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), change))
	newLease, newView := f.acquire(t)
	newTransport, _ := newView.DNSTransportManager().Transport("fixture")
	if newTransport == oldTransport || newView.componentIDs["dns-transport:fixture"] == oldView.componentIDs["dns-transport:fixture"] {
		t.Fatal("changed DNS options reused the old transport")
	}
	query(newLease, newTransport, "192.0.2.54")
	wireServer.waitProbe(t, "192.0.2.54")
	query(oldLease, oldTransport, "192.0.2.53")
	oldResource := runtimeTestResource(t, f, oldView.componentIDs["dns-transport:fixture"])
	select {
	case <-oldResource.owner.Closed():
		t.Fatal("old graph lease lost the original DNS transport")
	default:
	}
}
