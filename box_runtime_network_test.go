package box

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/route"
)

func TestRuntimeNetworkInventoryOptionalRouter(t *testing.T) {
	outbound := &runtimeTestSocks{}
	endpoint := &runtimeClientEndpointFixture{}
	router := &route.Router{}
	for _, test := range []struct {
		name      string
		component *runtimeComponent
		ready     bool
		retired   bool
		exhausted bool
		want      int
	}{
		{"empty", &runtimeComponent{}, true, false, false, 0},
		{"outbound-only", &runtimeComponent{outbound: outbound}, true, false, false, 1},
		{"router-only", &runtimeComponent{router: router}, true, false, false, 1},
		{"outbound-and-router", &runtimeComponent{outbound: outbound, router: router}, true, false, false, 1},
		{"endpoint-only", &runtimeComponent{endpoint: endpoint}, true, false, false, 1},
		{"not-ready", &runtimeComponent{outbound: outbound}, false, false, false, 0},
		{"retained-retired-outbound", &runtimeComponent{outbound: outbound}, true, true, false, 1},
		{"exhausted-outbound", &runtimeComponent{outbound: outbound}, true, true, true, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := adapter.RuntimeResourceID{Incarnation: test.name, Sequence: 1}
			owner, err := runtimegraph.NewResourceOwner(context.Background(), id, nil, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			lease, err := owner.Acquire()
			if err != nil {
				t.Fatal(err)
			}
			waitClosed := func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := owner.WaitClosed(ctx); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() {
				owner.Seal()
				lease.Release()
				waitClosed()
			})
			if test.retired {
				owner.Seal()
			}
			if test.exhausted {
				lease.Release()
				waitClosed()
			}
			c := &runtimeCoordinator{catalog: map[adapter.RuntimeResourceID]*runtimeResource{
				id: {owner: owner, networkReady: test.ready, components: map[string]*runtimeComponent{"component": test.component}},
			}}
			calls := 0
			c.VisitRuntimeNetwork(context.Background(), func(ctx context.Context, gotOutbound adapter.Outbound, gotRouter adapter.Router) {
				calls++
				if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, id); !ok {
					t.Error("network callback lost its retained resource lease")
				}
				wantOutbound := test.component.outbound
				if test.component.endpoint != nil {
					wantOutbound = test.component.endpoint
				}
				if gotOutbound != wantOutbound {
					t.Error("network callback changed the outbound or endpoint")
				}
				if test.component.router == nil {
					if gotRouter != nil {
						t.Fatal("absent router became a non-nil interface in the network callback")
					}
				} else if gotRouter != test.component.router {
					t.Error("network callback changed the live router")
				}
			})
			if calls != test.want {
				t.Fatalf("network callback count = %d, want %d", calls, test.want)
			}
		})
	}
}

func TestRuntimeNetworkResetWithOutboundOnlyResources(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	// Exercise the actual NetworkManager callback that crashed on interface
	// updates, rather than making Router.ResetNetwork silently accept nil.
	f.box.network.ResetNetwork(context.Background())
}
