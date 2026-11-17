package tun

import (
	"errors"
	"github.com/sagernet/sing/common/control"
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func TestRedirectRouteReceiptsDoNotClaimFailedAdd(t *testing.T) {
	r := &autoRedirect{}
	route := newRedirectRoute(1001, redirectRouteKey{linkIndex: 7, family: unix.AF_INET})
	if err := r.addOwnedRedirectRoute(&route, func(*netlink.Route) error { return unix.EEXIST }); !errors.Is(err, unix.EEXIST) {
		t.Fatal(err)
	}
	deletes := 0
	if err := r.clearOwnedRedirectRoutes(func(*netlink.Route) error { deletes++; return nil }, func(*netlink.Rule) error { deletes++; return nil }); err != nil {
		t.Fatal(err)
	}
	if deletes != 0 {
		t.Fatal("attempted deletion of an unowned object")
	}
}

func TestRedirectRouteCleanupRetainsIndependentFailures(t *testing.T) {
	r := &autoRedirect{}
	a := newRedirectRoute(1001, redirectRouteKey{linkIndex: 7, family: unix.AF_INET})
	b := newRedirectRoute(1001, redirectRouteKey{linkIndex: 8, family: unix.AF_INET6})
	for _, v := range []netlink.Route{a, b} {
		if err := r.addOwnedRedirectRoute(&v, func(*netlink.Route) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	rule := netlink.NewRule()
	rule.Priority = 1
	rule.Table = 1001
	r.redirectOwnedRules.rules = []*netlink.Rule{rule}
	denyRoute, denyRule := errors.New("route denied"), errors.New("rule denied")
	count := 0
	err := r.clearOwnedRedirectRoutes(func(route *netlink.Route) error {
		count++
		if route.LinkIndex == 7 {
			return denyRoute
		}
		return nil
	}, func(*netlink.Rule) error { return denyRule })
	if !errors.Is(err, denyRoute) || !errors.Is(err, denyRule) || count != 2 {
		t.Fatalf("not all cleanup attempted: %v %d", err, count)
	}
	if len(r.redirectOwnedRoutes.routes) != 1 || r.redirectOwnedRoutes.routes[0].LinkIndex != 7 || len(r.redirectOwnedRules.rules) != 1 {
		t.Fatal("cleanup debt not retained precisely")
	}
	count = 0
	err = r.clearOwnedRedirectRoutes(func(route *netlink.Route) error {
		count++
		if route.LinkIndex != 7 {
			t.Fatal("retried successful removal")
		}
		return unix.ESRCH
	}, func(*netlink.Rule) error { return unix.ENOENT })
	if err != nil || count != 1 || len(r.redirectOwnedRoutes.routes) != 0 || len(r.redirectOwnedRules.rules) != 0 {
		t.Fatal("retry did not clear debt", err)
	}
}

func TestRedirectMissingOwnedRouteRestoredWithoutAdoptingForeign(t *testing.T) {
	r := &autoRedirect{redirectRouteTableIndex: 1001, enableIPv4: true}
	owned := newRedirectRoute(1001, redirectRouteKey{linkIndex: 7, family: unix.AF_INET})
	foreign := newRedirectRoute(1001, redirectRouteKey{linkIndex: 9, family: unix.AF_INET})
	r.redirectOwnedRoutes.routes = []netlink.Route{owned}
	iface := control.Interface{Index: 7, Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}
	added := 0
	err := r.reconcileRedirectRoutesWith([]control.Interface{iface}, func() ([]netlink.Route, error) { return []netlink.Route{foreign}, nil }, func(route *netlink.Route) error {
		added++
		if !route.Equal(owned) {
			t.Fatal("unexpected addition")
		}
		return nil
	}, func(*netlink.Route) error { t.Fatal("deleted foreign route"); return nil })
	if err != nil || added != 1 || len(r.redirectOwnedRoutes.routes) != 1 || !r.redirectOwnedRoutes.routes[0].Equal(owned) {
		t.Fatal("missing route not repaired", err)
	}
}

func TestRedirectLiveQueryFailureKeepsDebtAndDoesNotMutate(t *testing.T) {
	r := &autoRedirect{redirectRouteTableIndex: 1001, enableIPv4: true}
	owned := newRedirectRoute(1001, redirectRouteKey{linkIndex: 7, family: unix.AF_INET})
	r.redirectOwnedRoutes.routes = []netlink.Route{owned}
	denied := errors.New("list failed")
	mutate := func(*netlink.Route) error { t.Fatal("mutated on unknown live state"); return nil }
	err := r.reconcileRedirectRoutesWith(nil, func() ([]netlink.Route, error) { return nil, denied }, mutate, mutate)
	if !errors.Is(err, denied) || len(r.redirectOwnedRoutes.routes) != 1 {
		t.Fatal("unknown became absent", err)
	}
}

func TestRedirectIPv6KernelDefaultsAndDynamicFlagsRetainOwnership(t *testing.T) {
	r := &autoRedirect{redirectRouteTableIndex: 1001, enableIPv6: true}
	owned := newRedirectRoute(1001, redirectRouteKey{linkIndex: 7, family: unix.AF_INET6})
	if owned.Priority != 1024 {
		t.Fatal("IPv6 metric must be explicit")
	}
	owned.Priority = 0 // receipt predating explicit metric normalization
	live := owned
	live.Priority = 1024
	live.Flags = unix.RTNH_F_LINKDOWN
	r.redirectOwnedRoutes.routes = []netlink.Route{owned}
	iface := control.Interface{Index: 7, Addresses: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/64")}}
	mutate := func(*netlink.Route) error { t.Fatal("normalized live route treated as absent"); return nil }
	err := r.reconcileRedirectRoutesWith([]control.Interface{iface}, func() ([]netlink.Route, error) { return []netlink.Route{live}, nil }, mutate, mutate)
	if err != nil || len(r.redirectOwnedRoutes.routes) != 1 {
		t.Fatal("lost normalized ownership", err)
	}
}

func TestRedirectUnexplainedLiveSelectorChangePreservesAllDebt(t *testing.T) {
	r := &autoRedirect{redirectRouteTableIndex: 1001, enableIPv6: true}
	owned := newRedirectRoute(1001, redirectRouteKey{linkIndex: 7, family: unix.AF_INET6})
	other := newRedirectRoute(1001, redirectRouteKey{linkIndex: 8, family: unix.AF_INET6})
	live := owned
	live.Priority = 999
	r.redirectOwnedRoutes.routes = []netlink.Route{other, owned}
	mutate := func(*netlink.Route) error { t.Fatal("mutated ambiguous ownership"); return nil }
	err := r.reconcileRedirectRoutesWith(nil, func() ([]netlink.Route, error) { return []netlink.Route{live}, nil }, mutate, mutate)
	if err == nil || len(r.redirectOwnedRoutes.routes) != 2 || !r.redirectOwnedRoutes.routes[0].Equal(other) {
		t.Fatal("uncertainty lost cleanup debt", err)
	}
}

func TestRedirectLegacyIPv6RemovalUsesExactNormalizedMetric(t *testing.T) {
	r := &autoRedirect{redirectRouteTableIndex: 1001, enableIPv6: true}
	receipt := newRedirectRoute(1001, redirectRouteKey{linkIndex: 7, family: unix.AF_INET6})
	live := receipt
	receipt.Priority = 0
	r.redirectOwnedRoutes.routes = []netlink.Route{receipt}
	removed := 0
	err := r.reconcileRedirectRoutesWith(nil, func() ([]netlink.Route, error) { return []netlink.Route{live}, nil }, func(*netlink.Route) error { t.Fatal("unexpected add"); return nil }, func(route *netlink.Route) error {
		removed++
		if route.Priority != 1024 {
			t.Fatal("imprecise IPv6 delete")
		}
		return nil
	})
	if err != nil || removed != 1 || len(r.redirectOwnedRoutes.routes) != 0 {
		t.Fatal("legacy removal not complete", err)
	}
}
