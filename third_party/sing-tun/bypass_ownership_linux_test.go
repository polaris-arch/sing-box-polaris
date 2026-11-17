//go:build linux

package tun

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

type bypassFixture struct {
	routes                  []netlink.Route
	rules                   []netlink.Rule
	mutations               int
	listErr, addErr, delErr error
}

func (f *bypassFixture) ops() bypassOps {
	return bypassOps{
		routes: func(family int) ([]netlink.Route, error) {
			var result []netlink.Route
			for _, r := range f.routes {
				if bypassFamily(r) == family {
					result = append(result, r)
				}
			}
			return result, f.listErr
		},
		rules: func(family int) ([]netlink.Rule, error) {
			var result []netlink.Rule
			for _, r := range f.rules {
				if r.Family == family {
					result = append(result, r)
				}
			}
			return result, f.listErr
		},
		addRoute: func(r *netlink.Route) error {
			f.mutations++
			if f.addErr != nil {
				return f.addErr
			}
			c, _ := cloneBypassRoute(*r)
			f.routes = append(f.routes, c)
			return nil
		},
		delRoute: func(r *netlink.Route) error {
			f.mutations++
			if f.delErr != nil {
				return f.delErr
			}
			for i, x := range f.routes {
				if bypassRouteSame(x, *r) {
					f.routes = append(f.routes[:i], f.routes[i+1:]...)
					return nil
				}
			}
			return unix.ESRCH
		},
		addRule: func(r *netlink.Rule) error {
			f.mutations++
			if f.addErr != nil {
				return f.addErr
			}
			f.rules = append(f.rules, *cloneBypassRule(r))
			return nil
		},
		delRule: func(r *netlink.Rule) error {
			f.mutations++
			if f.delErr != nil {
				return f.delErr
			}
			for i, x := range f.rules {
				if bypassRuleSame(&x, r) {
					f.rules = append(f.rules[:i], f.rules[i+1:]...)
					return nil
				}
			}
			return unix.ENOENT
		},
	}
}
func bypassTestRoute() netlink.Route {
	_, dst, _ := net.ParseCIDR("192.0.2.0/24")
	return netlink.Route{Table: 700, Family: unix.AF_INET, LinkIndex: 5, Dst: dst, Gw: net.ParseIP("198.51.100.1"), Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_STATIC}
}
func bypassTestRule() *netlink.Rule {
	r := netlink.NewRule()
	r.Table = 700
	r.Family = unix.AF_INET
	r.Priority = 11000
	r.Invert = true
	r.Dport = netlink.NewRulePortRange(53, 53)
	return r
}
func TestBypassOwnedStableAndPreciseCleanup(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{}
	d := bypassTestRoute()
	rule := bypassTestRule()
	if _, e := o.reconcile(unix.AF_INET, []netlink.Route{d}, rule, f.ops()); e != nil {
		t.Fatal(e)
	}
	before := f.mutations
	if n, e := o.reconcile(unix.AF_INET, []netlink.Route{d}, rule, f.ops()); e != nil || n != 0 || f.mutations != before {
		t.Fatalf("churn n=%d e=%v", n, e)
	}
	foreign := d
	_, foreign.Dst, _ = net.ParseCIDR("203.0.113.0/24")
	f.routes = append(f.routes, foreign)
	if e := o.clear(f.ops()); e != nil {
		t.Fatal(e)
	}
	if len(f.routes) != 1 || !bypassRouteSame(f.routes[0], foreign) || len(f.rules) != 0 || len(o.routes) != 0 {
		t.Fatal("foreign resource touched or debt remains")
	}
}
func TestBypassForeignRouteAndRuleNotAdopted(t *testing.T) {
	for _, kind := range []string{"route", "rule"} {
		t.Run(kind, func(t *testing.T) {
			var o bypassOwner
			f := &bypassFixture{}
			d := bypassTestRoute()
			r := bypassTestRule()
			if kind == "route" {
				f.routes = []netlink.Route{d}
			} else {
				f.rules = []netlink.Rule{*r}
			}
			if _, e := o.reconcile(unix.AF_INET, []netlink.Route{d}, r, f.ops()); e == nil || f.mutations != 0 || len(o.routes) != 0 || len(o.rules) != 0 {
				t.Fatal("foreign adopted or mutated")
			}
		})
	}
}
func TestBypassFailedAddNeverOwned(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{addErr: unix.EEXIST}
	if _, e := o.reconcile(unix.AF_INET, []netlink.Route{bypassTestRoute()}, nil, f.ops()); e == nil || len(o.routes) != 0 {
		t.Fatal("failed add owned")
	}
	before := f.mutations
	if e := o.clear(f.ops()); e != nil || f.mutations != before {
		t.Fatal("cleanup of failed add")
	}
}
func TestBypassQueryAndDeleteFailureKeepDebt(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{}
	if _, e := o.reconcile(unix.AF_INET, []netlink.Route{bypassTestRoute()}, bypassTestRule(), f.ops()); e != nil {
		t.Fatal(e)
	}
	before := f.mutations
	f.listErr = errors.New("query unavailable")
	if e := o.clear(f.ops()); e == nil || f.mutations != before || len(o.routes) != 1 || len(o.rules) != 1 {
		t.Fatal("query failure lost debt")
	}
	f.listErr = nil
	f.delErr = unix.EPERM
	if e := o.clear(f.ops()); e == nil || len(o.routes) != 1 || len(o.rules) != 1 {
		t.Fatal("delete failure lost debt")
	}
	f.delErr = nil
	if e := o.clear(f.ops()); e != nil || len(o.routes) != 0 || len(o.rules) != 0 {
		t.Fatal("retry failed")
	}
}
func TestBypassChangedSelectorsDoNotDeleteReplacement(t *testing.T) {
	for _, kind := range []string{"gateway", "dport", "invert"} {
		t.Run(kind, func(t *testing.T) {
			var o bypassOwner
			f := &bypassFixture{}
			o.reconcile(unix.AF_INET, []netlink.Route{bypassTestRoute()}, bypassTestRule(), f.ops())
			before := f.mutations
			switch kind {
			case "gateway":
				f.routes[0].Gw = net.ParseIP("198.51.100.2")
			case "dport":
				f.rules[0].Dport = netlink.NewRulePortRange(54, 54)
			case "invert":
				f.rules[0].Invert = false
			}
			if e := o.clear(f.ops()); e == nil || f.mutations != before || len(o.routes) != 1 || len(o.rules) != 1 {
				t.Fatal("changed external resource removed")
			}
		})
	}
}
func TestBypassRouteUpdateAndMissingRepair(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{}
	d := bypassTestRoute()
	o.reconcile(unix.AF_INET, []netlink.Route{d}, nil, f.ops())
	d.Gw = net.ParseIP("198.51.100.2")
	if n, e := o.reconcile(unix.AF_INET, []netlink.Route{d}, nil, f.ops()); e != nil || n != 2 || len(o.routes) != 1 {
		t.Fatalf("update n=%d e=%v", n, e)
	}
	f.routes = nil
	if n, e := o.reconcile(unix.AF_INET, []netlink.Route{d}, nil, f.ops()); e != nil || n != 1 {
		t.Fatalf("repair n=%d e=%v", n, e)
	}
}
func TestBypassReceiptDeepCopyAndIPv6Metric(t *testing.T) {
	d := bypassTestRoute()
	_, d.Src, _ = net.ParseCIDR("198.51.100.0/24")
	d.MultiPath = []*netlink.NexthopInfo{{LinkIndex: 6, Gw: net.ParseIP("198.51.100.3")}}
	c, e := cloneBypassRoute(d)
	if e != nil {
		t.Fatal(e)
	}
	d.Src.IP[0] = 1
	d.MultiPath[0].Gw[0] = 1
	if reflect.DeepEqual(c.Src, d.Src) || reflect.DeepEqual(c.MultiPath, d.MultiPath) {
		t.Fatal("aliased receipt")
	}
	d = netlink.Route{Family: unix.AF_INET6, Table: 700, Type: unix.RTN_UNICAST}
	live := d
	live.Dst = defaultDestination(unix.AF_INET6)
	live.Priority = 1024
	live.Flags = unix.RTNH_F_LINKDOWN
	if !bypassRouteSame(d, live) {
		t.Fatal("kernel default metric/health flags mismatch")
	}
}

func TestBypassLargeStableSetNoMutation(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{}
	desired := make([]netlink.Route, 4096)
	for i := range desired {
		r := bypassTestRoute()
		r.Dst = &net.IPNet{IP: net.IPv4(10, byte(i>>8), byte(i), 1), Mask: net.CIDRMask(32, 32)}
		desired[i] = r
	}
	if _, err := o.reconcile(unix.AF_INET, desired, nil, f.ops()); err != nil {
		t.Fatal(err)
	}
	before := f.mutations
	if n, err := o.reconcile(unix.AF_INET, desired, nil, f.ops()); err != nil || n != 0 || f.mutations != before {
		t.Fatalf("stable set churn %d %v", n, err)
	}
}

func TestBypassIndependentDeleteFailureRetainsOnlyFailedReceipt(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{}
	a := bypassTestRoute()
	b := a
	_, b.Dst, _ = net.ParseCIDR("203.0.113.0/24")
	if _, err := o.reconcile(unix.AF_INET, []netlink.Route{a, b}, nil, f.ops()); err != nil {
		t.Fatal(err)
	}
	ops := f.ops()
	remove := ops.delRoute
	ops.delRoute = func(r *netlink.Route) error {
		if r.Dst.String() == a.Dst.String() {
			return unix.EPERM
		}
		return remove(r)
	}
	if err := o.clear(ops); err == nil || len(o.routes) != 1 || !bypassRouteSame(o.routes[0], a) {
		t.Fatalf("remaining=%v err=%v", o.routes, err)
	}
	if err := o.clear(f.ops()); err != nil || len(o.routes) != 0 {
		t.Fatal("retry failed")
	}
}

func TestBypassFailedRuleAddKeepsOnlySuccessfulRouteReceipt(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{}
	ops := f.ops()
	ops.addRule = func(*netlink.Rule) error { return unix.EEXIST }
	if _, err := o.reconcile(unix.AF_INET, []netlink.Route{bypassTestRoute()}, bypassTestRule(), ops); err == nil || len(o.routes) != 1 || len(o.rules) != 0 {
		t.Fatal("failed rule was adopted or successful route receipt lost")
	}
	if err := o.clear(f.ops()); err != nil || len(f.routes) != 0 {
		t.Fatal("rollback failed")
	}
}

func TestBypassRejectsAmbiguousAndUnsupportedReceipts(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{}
	d := bypassTestRoute()
	if _, err := o.reconcile(unix.AF_INET, []netlink.Route{d}, nil, f.ops()); err != nil {
		t.Fatal(err)
	}
	f.routes = append(f.routes, f.routes[0])
	before := f.mutations
	if err := o.clear(f.ops()); err == nil || f.mutations != before || len(o.routes) != 1 {
		t.Fatal("ambiguous receipt cleared")
	}
	var empty bypassOwner
	v := 5
	d.MPLSDst = &v
	if _, err := empty.reconcile(unix.AF_INET, []netlink.Route{d}, nil, (&bypassFixture{}).ops()); err == nil {
		t.Fatal("unsupported destination accepted")
	}
}

func TestBypassUnspecifiedTypeUsesKernelUnicastDefault(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{}
	d := bypassTestRoute()
	d.Type = 0
	if _, err := o.reconcile(unix.AF_INET, []netlink.Route{d}, nil, f.ops()); err != nil {
		t.Fatal(err)
	}
	if f.routes[0].Type != unix.RTN_UNICAST || o.routes[0].Type != unix.RTN_UNICAST {
		t.Fatal("type default not recorded")
	}
	before := f.mutations
	if n, err := o.reconcile(unix.AF_INET, []netlink.Route{d}, nil, f.ops()); err != nil || n != 0 || f.mutations != before {
		t.Fatalf("kernel type readback churn %d %v", n, err)
	}
}

func bypassRouteSame(a, b netlink.Route) bool {
	a, e := cloneBypassRoute(a)
	if e != nil {
		return false
	}
	b, e = cloneBypassRoute(b)
	return e == nil && reflect.DeepEqual(a, b)
}

func TestBypassMixedFamilyCleanupPreservesOtherFamily(t *testing.T) {
	var o bypassOwner
	f := &bypassFixture{}
	v4 := bypassTestRoute()
	r4 := bypassTestRule()
	v6 := bypassTestRoute()
	v6.Family = unix.AF_INET6
	_, v6.Dst, _ = net.ParseCIDR("2001:db8::/64")
	v6.Gw = net.ParseIP("2001:db8:1::1")
	r6 := bypassTestRule()
	r6.Family = unix.AF_INET6
	for _, item := range []struct {
		route netlink.Route
		rule  *netlink.Rule
	}{{v4, r4}, {v6, r6}} {
		if _, err := o.reconcile(item.route.Family, []netlink.Route{item.route}, item.rule, f.ops()); err != nil {
			t.Fatal(err)
		}
	}
	before := f.mutations
	if n, err := o.reconcile(unix.AF_INET, nil, nil, f.ops()); err != nil || n != 2 {
		t.Fatalf("cleanup: %d %v", n, err)
	}
	if len(o.routes) != 1 || len(o.rules) != 1 || len(f.routes) != 1 || len(f.rules) != 1 || !bypassRouteSame(f.routes[0], v6) || !bypassRuleSame(&f.rules[0], r6) || f.mutations != before+2 {
		t.Fatal("other family lost or cleanup incomplete")
	}
	before = f.mutations
	if n, err := o.reconcile(unix.AF_INET6, []netlink.Route{v6}, r6, f.ops()); err != nil || n != 0 || f.mutations != before {
		t.Fatalf("IPv6 churn: %d %v", n, err)
	}
	if err := o.clear(f.ops()); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 0 || len(f.rules) != 0 {
		t.Fatal("remaining family not cleaned")
	}
}

func TestBypassForeignOtherPriorityPreserved(t *testing.T) {
	var o bypassOwner
	rule := bypassTestRule()
	foreign := cloneBypassRule(rule)
	foreign.Priority++
	f := &bypassFixture{rules: []netlink.Rule{*foreign}}
	d := bypassTestRoute()
	if _, err := o.reconcile(unix.AF_INET, []netlink.Route{d}, rule, f.ops()); err != nil {
		t.Fatal(err)
	}
	before := f.mutations
	if n, err := o.reconcile(unix.AF_INET, []netlink.Route{d}, rule, f.ops()); err != nil || n != 0 || f.mutations != before {
		t.Fatalf("churn: %d %v", n, err)
	}
	if err := o.clear(f.ops()); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 0 || len(o.routes) != 0 || len(o.rules) != 0 || len(f.rules) != 1 || !bypassRuleSame(&f.rules[0], foreign) {
		t.Fatal("foreign priority touched or owned debt remains")
	}
}
