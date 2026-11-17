//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"reflect"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// Serialized by bypassRouteAccess. Only successful adds establish receipts.
// Readback is not a CAS: identical external replacement cannot be distinguished.
type bypassOwner struct {
	routes []netlink.Route
	rules  []*netlink.Rule
}
type bypassOps struct {
	routes             func(int) ([]netlink.Route, error)
	rules              func(int) ([]netlink.Rule, error)
	addRoute, delRoute func(*netlink.Route) error
	addRule, delRule   func(*netlink.Rule) error
}

func bypassKernelOps(table int) bypassOps {
	return bypassOps{
		routes: func(f int) ([]netlink.Route, error) {
			return netlink.RouteListFiltered(f, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		},
		rules:    netlink.RuleList,
		addRoute: netlink.RouteAdd,
		delRoute: netlink.RouteDel,
		addRule:  netlink.RuleAdd,
		delRule:  netlink.RuleDel,
	}
}
func bypassFamily(r netlink.Route) int {
	if r.Family != 0 {
		return r.Family
	}
	if r.Dst != nil && r.Dst.IP.To4() != nil {
		return unix.AF_INET
	}
	return unix.AF_INET6
}
func bypassIP(ip net.IP) net.IP {
	if len(ip) == 0 {
		return nil
	}
	if v := ip.To4(); v != nil {
		return append(net.IP(nil), v...)
	}
	return append(net.IP(nil), ip.To16()...)
}
func bypassNet(n *net.IPNet) *net.IPNet {
	if n == nil {
		return nil
	}
	return &net.IPNet{IP: bypassIP(n.IP), Mask: append(net.IPMask(nil), n.Mask...)}
}
func cloneBypassRoute(r netlink.Route) (netlink.Route, error) {
	if r.MPLSDst != nil || r.NewDst != nil || r.Encap != nil || r.Via != nil {
		return r, errors.New("unsupported bypass route encapsulation")
	}
	// netlink.NewRtMsg defaults unspecified route type to unicast. The
	// bypass source builder accepts only unspecified/unicast sources.
	if r.Type == 0 {
		r.Type = unix.RTN_UNICAST
	}
	r.Family = bypassFamily(r)
	if r.Dst == nil {
		r.Dst = defaultDestination(r.Family)
	}
	r.Dst = bypassNet(r.Dst)
	r.Src = bypassNet(r.Src)
	r.Gw = bypassIP(r.Gw)
	r = normalizeRedirectReceipt(r)
	r.Flags &^= unix.RTNH_F_DEAD | unix.RTNH_F_LINKDOWN
	if len(r.MultiPath) == 0 {
		r.MultiPath = nil
	} else {
		hops := make([]*netlink.NexthopInfo, len(r.MultiPath))
		for i, n := range r.MultiPath {
			if n == nil || n.NewDst != nil || n.Encap != nil || n.Via != nil {
				return r, errors.New("unsupported bypass nexthop")
			}
			c := *n
			c.Gw = bypassIP(c.Gw)
			c.Flags &^= unix.RTNH_F_DEAD | unix.RTNH_F_LINKDOWN
			hops[i] = &c
		}
		r.MultiPath = hops
	}
	return r, nil
}
func cloneBypassRule(r *netlink.Rule) *netlink.Rule {
	c := *r
	if r.Dport != nil {
		p := *r.Dport
		c.Dport = &p
	}
	if r.Sport != nil {
		p := *r.Sport
		c.Sport = &p
	}
	if r.UIDRange != nil {
		p := *r.UIDRange
		c.UIDRange = &p
	}
	return &c
}
func bypassRuleSame(a, b *netlink.Rule) bool { return reflect.DeepEqual(a, b) }
func bypassAbsent(err error) bool {
	return err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH)
}

// Preflight the whole family before any mutation. Foreign routes outside owned
// and desired slots remain untouched; a changed/ambiguous owned slot is debt.
type bypassSlotKey struct {
	family, table int
	destination   string
}

func bypassKey(r netlink.Route) bypassSlotKey {
	dst := r.Dst
	if dst == nil {
		dst = defaultDestination(bypassFamily(r))
	}
	return bypassSlotKey{bypassFamily(r), r.Table, dst.String()}
}

type bypassRuleSlotKey struct {
	family, table, priority int
}

func bypassRuleKey(r *netlink.Rule) bypassRuleSlotKey {
	return bypassRuleSlotKey{r.Family, r.Table, r.Priority}
}

func (o *bypassOwner) reconcile(family int, desired []netlink.Route, wanted *netlink.Rule, ops bypassOps) (int, error) {
	current, err := ops.routes(family)
	if err != nil {
		return 0, fmt.Errorf("list bypass routes: %w", err)
	}
	rules, err := ops.rules(family)
	if err != nil {
		return 0, fmt.Errorf("list bypass rules: %w", err)
	}
	// Index by family/table/prefix once. Reconciliation stays linear in the route
	// count; canonical copies are made once, not for every desired/live pair.
	live := make(map[bypassSlotKey][]netlink.Route, len(current))
	for _, r := range current {
		key := bypassKey(r)
		live[key] = append(live[key], r)
	}
	want := make(map[bypassSlotKey]netlink.Route, len(desired))
	for i, r := range desired {
		c, e := cloneBypassRoute(r)
		if e != nil {
			return 0, e
		}
		key := bypassKey(c)
		if _, ok := want[key]; ok {
			return 0, errors.New("duplicate desired bypass slot")
		}
		want[key] = c
		desired[i] = c
	}
	present := make(map[bypassSlotKey]bool, len(o.routes))
	for _, receipt := range o.routes {
		if bypassFamily(receipt) != family {
			continue
		}
		key := bypassKey(receipt)
		objects := live[key]
		if len(objects) > 1 {
			return 0, errors.New("ambiguous owned bypass route")
		}
		if len(objects) == 1 {
			c, e := cloneBypassRoute(objects[0])
			if e != nil || !reflect.DeepEqual(receipt, c) {
				return 0, errors.New("owned bypass route changed")
			}
			present[key] = true
		}
	}
	for key := range want {
		if len(live[key]) > 0 && !present[key] {
			return 0, errors.New("foreign bypass route conflicts")
		}
	}
	liveRules := make(map[bypassRuleSlotKey][]netlink.Rule, len(rules))
	for _, r := range rules {
		key := bypassRuleKey(&r)
		liveRules[key] = append(liveRules[key], r)
	}
	rulePresent := make([]bool, len(o.rules))
	for i, receipt := range o.rules {
		if receipt.Family != family {
			continue
		}
		objects := liveRules[bypassRuleKey(receipt)]
		if len(objects) > 1 {
			return 0, errors.New("ambiguous owned bypass rule")
		}
		if len(objects) == 1 {
			if !bypassRuleSame(receipt, &objects[0]) {
				return 0, errors.New("owned bypass rule changed")
			}
			rulePresent[i] = true
		}
	}
	if wanted != nil && len(liveRules[bypassRuleKey(wanted)]) > 0 {
		owned := false
		for i, r := range o.rules {
			if rulePresent[i] && bypassRuleKey(r) == bypassRuleKey(wanted) {
				owned = true
				break
			}
		}
		if !owned {
			return 0, errors.New("foreign bypass rule conflicts")
		}
	}
	var errs []error
	changed := 0
	oldRules := o.rules
	keptRules := oldRules[:0]
	for i, r := range oldRules {
		if r.Family != family {
			keptRules = append(keptRules, r)
			continue
		}
		if !rulePresent[i] {
			continue
		}
		if wanted != nil && bypassRuleSame(r, wanted) {
			keptRules = append(keptRules, r)
			continue
		}
		if e := ops.delRule(cloneBypassRule(r)); !bypassAbsent(e) {
			keptRules = append(keptRules, r)
			errs = append(errs, e)
		} else {
			changed++
		}
	}
	clear(oldRules[len(keptRules):])
	o.rules = keptRules
	if len(errs) > 0 {
		return changed, errors.Join(errs...)
	}
	oldRoutes := o.routes
	kept := oldRoutes[:0]
	retained := make(map[bypassSlotKey]bool, len(oldRoutes))
	for _, r := range oldRoutes {
		if bypassFamily(r) != family {
			kept = append(kept, r)
			continue
		}
		key := bypassKey(r)
		if !present[key] {
			continue
		}
		if d, ok := want[key]; ok && reflect.DeepEqual(r, d) {
			kept = append(kept, r)
			retained[key] = true
			continue
		}
		c, _ := cloneBypassRoute(r)
		if e := ops.delRoute(&c); !bypassAbsent(e) {
			kept = append(kept, r)
			errs = append(errs, e)
		} else {
			changed++
		}
	}
	clear(oldRoutes[len(kept):])
	o.routes = kept
	if len(errs) > 0 {
		return changed, errors.Join(errs...)
	}
	for _, d := range desired {
		if retained[bypassKey(d)] {
			continue
		}
		c, _ := cloneBypassRoute(d)
		if err := ops.addRoute(&c); err != nil {
			return changed, err
		}
		receipt, _ := cloneBypassRoute(d)
		o.routes = append(o.routes, receipt)
		changed++
	}
	if wanted != nil {
		exists := false
		for _, r := range o.rules {
			if bypassRuleSame(r, wanted) {
				exists = true
				break
			}
		}
		if !exists {
			if err := ops.addRule(cloneBypassRule(wanted)); err != nil {
				return changed, err
			}
			o.rules = append(o.rules, cloneBypassRule(wanted))
			changed++
		}
	}
	return changed, nil
}
func (o *bypassOwner) clear(ops bypassOps) error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		owned := false
		for _, r := range o.routes {
			owned = owned || bypassFamily(r) == family
		}
		for _, r := range o.rules {
			owned = owned || r.Family == family
		}
		if owned {
			_, err := o.reconcile(family, nil, nil, ops)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
