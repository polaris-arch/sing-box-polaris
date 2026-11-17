package tun

import (
	"errors"
	"net"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func ownershipRoute(table int) netlink.Route {
	return netlink.Route{Table: table, LinkIndex: 77, Dst: &net.IPNet{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(24, 32)}, Gw: net.IP{10, 0, 0, 1}}
}

func TestOwnedRoutesNeverClaimsExistingOrUnattemptedRoutes(t *testing.T) {
	var owner ownedLinuxRoutes
	var deleted []int
	routes := []netlink.Route{ownershipRoute(100), ownershipRoute(101), ownershipRoute(102)}
	err := owner.replace(func() ([]netlink.Route, error) { return routes, nil }, func(r *netlink.Route) error {
		if r.Table == 101 {
			return unix.EEXIST
		}
		return nil
	}, func(r *netlink.Route) error { deleted = append(deleted, r.Table); return nil })
	if !errors.Is(err, unix.EEXIST) || len(deleted) != 1 || deleted[0] != 100 || len(owner.routes) != 0 {
		t.Fatalf("foreign or unattempted route removed: deleted=%v debt=%v err=%v", deleted, owner.routes, err)
	}
}

func TestOwnedRoutesKeepExactReceiptsAndFailedDeletionDebt(t *testing.T) {
	var owner ownedLinuxRoutes
	routes := []netlink.Route{ownershipRoute(100), ownershipRoute(101)}
	if err := owner.install(routes, func(*netlink.Route) error { return nil }); err != nil {
		t.Fatal(err)
	}
	routes[0].Dst.IP[0] = 99
	routes[0].Gw[0] = 99
	failure := errors.New("delete failed")
	calls := 0
	err := owner.clear(func(r *netlink.Route) error {
		calls++
		if r.LinkIndex != 77 || r.Dst.IP[0] != 10 || r.Gw[0] != 10 {
			t.Error("receipt changed")
		}
		if r.Table == 100 {
			return failure
		}
		return nil
	})
	if !errors.Is(err, failure) || calls != 2 || len(owner.routes) != 1 {
		t.Fatalf("lost debt: %v", err)
	}
	added := false
	if err := owner.replace(func() ([]netlink.Route, error) { return []netlink.Route{ownershipRoute(102)}, nil }, func(*netlink.Route) error { added = true; return nil }, func(*netlink.Route) error { return failure }); !errors.Is(err, failure) || added {
		t.Fatal("installed over unresolved cleanup")
	}
	owner.closed = true
	if err := owner.clear(func(*netlink.Route) error { return unix.ESRCH }); err != nil || len(owner.routes) != 0 {
		t.Fatal("closed owner could not clear debt")
	}
	if err := owner.replace(func() ([]netlink.Route, error) { t.Fatal("closed owner built routes"); return nil, nil }, nil, nil); err == nil {
		t.Fatal("closed owner reopened")
	}
}

func TestOwnedRoutesRollbackRetainsAddAndDeleteFailures(t *testing.T) {
	var owner ownedLinuxRoutes
	addErr, delErr := errors.New("add"), errors.New("delete")
	err := owner.replace(func() ([]netlink.Route, error) { return []netlink.Route{ownershipRoute(1), ownershipRoute(2)}, nil }, func(r *netlink.Route) error {
		if r.Table == 2 {
			return addErr
		}
		return nil
	}, func(*netlink.Route) error { return delErr })
	if !errors.Is(err, addErr) || !errors.Is(err, delErr) || len(owner.routes) != 1 {
		t.Fatalf("rollback lost evidence: %v", err)
	}
}

func TestRouteUpdateCannotMoveNativeOwnership(t *testing.T) {
	base := Options{Name: "owned", NetNs: "original"}
	for _, mutate := range []func(*Options){
		func(o *Options) { o.Name = "other" },
		func(o *Options) { o.NetNs = "other" },
		func(o *Options) { o.FileDescriptor = 99 },
		func(o *Options) { o.EXP_ExternalConfiguration = true },
	} {
		tun := &NativeTun{options: base}
		next := base
		mutate(&next)
		if err := tun.UpdateRouteOptions(next); err == nil {
			t.Fatal("device ownership changed")
		}
		if tun.options.Name != base.Name || tun.options.NetNs != base.NetNs {
			t.Fatal("failed update published options")
		}
	}
}

func TestClosedNativeTunRejectsRouteUpdate(t *testing.T) {
	tun := &NativeTun{options: Options{Name: "owned"}, ownedRoutes: ownedLinuxRoutes{closed: true}}
	next := tun.options
	next.AutoRoute = true
	if err := tun.UpdateRouteOptions(next); err == nil {
		t.Fatal("closed native owner accepted route update")
	}
	if tun.options.AutoRoute {
		t.Fatal("closed owner published changed options")
	}
}
