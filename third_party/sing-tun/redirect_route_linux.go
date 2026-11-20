//go:build linux

package tun

import (
	"errors"
	"net"
	"slices"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const redirectRouteRulePriority = 1

func (r *autoRedirect) setupRedirectRoutes() (err error) {
	err = r.interfaceFinder.Update()
	if err != nil {
		return E.Cause(err, "update interfaces")
	}
	redirectInterfaces := r.currentRedirectInterfaces()
	r.redirectRouteAccess.Lock()
	defer r.redirectRouteAccess.Unlock()
	tableIndex, err := chooseRouteTableIndex(r.tunOptions.IPRoute2TableIndex, r.tproxyRouteTableIndex)
	if err != nil {
		return E.Cause(err, "select redirect route table")
	}
	r.redirectRoutesActive = false
	if err = r.cleanupRedirectRoutesLocked(); err != nil {
		return err
	}
	// Priority/table discovery is not ownership. Never sweep another live
	// instance's rules as a substitute for explicit crash recovery.
	r.redirectRouteTableIndex = tableIndex
	defer func() {
		if err != nil {
			err = errors.Join(err, r.cleanupRedirectRoutesLocked())
		}
	}()
	err = r.reconcileRedirectRoutesLocked(redirectInterfaces)
	if err != nil {
		return err
	}
	if r.enableIPv4 {
		rule := netlink.NewRule()
		rule.Priority = redirectRouteRulePriority
		rule.Table = r.redirectRouteTableIndex
		rule.Family = unix.AF_INET
		err = r.addOwnedRedirectRule(rule)
		if err != nil {
			return E.Cause(err, "add ipv4 redirect rule")
		}
	}
	if r.enableIPv6 {
		rule := netlink.NewRule()
		rule.Priority = redirectRouteRulePriority
		rule.Table = r.redirectRouteTableIndex
		rule.Family = unix.AF_INET6
		err = r.addOwnedRedirectRule(rule)
		if err != nil {
			return E.Cause(err, "add ipv6 redirect rule")
		}
	}
	if r.tproxyEnabled() {
		err = r.setupTProxyRouteLocked()
		if err != nil {
			return err
		}
	}
	r.redirectRoutesActive = true
	return nil
}

func (r *autoRedirect) setupTProxyRouteLocked() error {
	tableIndex, err := chooseRouteTableIndex(r.tunOptions.IPRoute2TableIndex, r.redirectRouteTableIndex)
	if err != nil {
		return E.Cause(err, "select tproxy route table")
	}
	r.tproxyRouteTableIndex = tableIndex
	loopbackLink, err := netlink.LinkByName("lo")
	if err != nil {
		return E.Cause(err, "find loopback interface")
	}
	route := netlink.Route{
		LinkIndex: loopbackLink.Attrs().Index,
		Dst:       defaultDestination(unix.AF_INET6),
		Priority:  1024, // IP6_RT_PRIO_USER, explicit to match kernel readback.
		Table:     r.tproxyRouteTableIndex,
		Type:      unix.RTN_LOCAL,
		Protocol:  unix.RTPROT_BOOT,
		Scope:     netlink.SCOPE_HOST,
	}
	err = r.addOwnedRedirectRoute(&route, netlink.RouteAdd)
	if err != nil {
		return E.Cause(err, "add tproxy route")
	}
	rule := r.tproxyRouteRule()
	err = r.addOwnedRedirectRule(rule)
	if err != nil {
		return E.Cause(err, "add tproxy rule")
	}
	return nil
}

func (r *autoRedirect) tproxyRouteRule() *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = redirectRouteRulePriority
	rule.Family = unix.AF_INET6
	rule.Mark = r.tunOptions.AutoRedirectTProxyMark
	rule.MarkSet = true
	rule.Mask = int(r.effectiveMarkMask())
	rule.Table = r.tproxyRouteTableIndex
	return rule
}

func (r *autoRedirect) currentRedirectInterfaces() []control.Interface {
	tunName := r.tunOptions.Name
	return common.Filter(r.interfaceFinder.Interfaces(), func(it control.Interface) bool {
		return it.Name != "lo" && it.Name != tunName && it.Flags&net.FlagUp != 0
	})
}

func redirectRouteAddressFamilies(iface control.Interface) (hasIPv4Address bool, hasIPv6Address bool) {
	for _, prefix := range iface.Addresses {
		address := prefix.Addr()
		if address.Is4() {
			hasIPv4Address = true
		} else if address.Is6() && !address.Is4In6() {
			hasIPv6Address = true
		}
	}
	return
}

func (r *autoRedirect) updateRedirectRoutes() error {
	err := r.interfaceFinder.Update()
	if err != nil {
		return E.Cause(err, "update interfaces")
	}
	redirectInterfaces := r.currentRedirectInterfaces()
	r.redirectRouteAccess.Lock()
	defer r.redirectRouteAccess.Unlock()
	if !r.redirectRoutesActive {
		return nil
	}
	return r.reconcileRedirectRoutesLocked(redirectInterfaces)
}

func (r *autoRedirect) cleanupRedirectRoutes() error {
	r.redirectRouteAccess.Lock()
	defer r.redirectRouteAccess.Unlock()
	r.redirectRoutesActive = false
	return r.cleanupRedirectRoutesLocked()
}

func (r *autoRedirect) cleanupRedirectRoutesLocked() error {
	return r.clearOwnedRedirectRoutes(netlink.RouteDel, netlink.RuleDel)
}

// Caller holds redirectRouteAccess. Every failed deletion keeps its receipt.
func (r *autoRedirect) clearOwnedRedirectRoutes(removeRoute func(*netlink.Route) error, removeRule func(*netlink.Rule) error) error {
	return errors.Join(r.redirectOwnedRules.clear(removeRule), r.redirectOwnedRoutes.clear(func(route *netlink.Route) error {
		normalized := normalizeRedirectReceipt(*route)
		return removeRoute(&normalized)
	}))
}

func (r *autoRedirect) addOwnedRedirectRoute(route *netlink.Route, add func(*netlink.Route) error) error {
	receipt := cloneOwnedRoute(*route)
	if err := add(route); err != nil {
		return err
	}
	r.redirectOwnedRoutes.routes = append(r.redirectOwnedRoutes.routes, receipt)
	return nil
}

func (r *autoRedirect) addOwnedRedirectRule(rule *netlink.Rule) error {
	if err := netlink.RuleAdd(rule); err != nil {
		return err
	}
	receipt := *rule
	r.redirectOwnedRules.rules = append(r.redirectOwnedRules.rules, &receipt)
	return nil
}

type redirectRouteKey struct {
	linkIndex int
	family    int
}

func (r *autoRedirect) reconcileRedirectRoutesLocked(redirectInterfaces []control.Interface) error {
	return r.reconcileRedirectRoutesWith(redirectInterfaces, func() ([]netlink.Route, error) {
		return netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: r.redirectRouteTableIndex}, netlink.RT_FILTER_TABLE)
	}, netlink.RouteAppend, netlink.RouteDel)
}

func (r *autoRedirect) reconcileRedirectRoutesWith(redirectInterfaces []control.Interface, listLive func() ([]netlink.Route, error), add, remove func(*netlink.Route) error) error {
	live, err := listLive()
	if err != nil {
		return E.Cause(err, "list live redirect routes")
	}
	// Receipts prove origin, not continued existence. Drop only receipts
	// positively absent from this successful live snapshot; do not adopt foreign.
	var currentRoutes []netlink.Route
	retained := make([]netlink.Route, 0, len(r.redirectOwnedRoutes.routes))
	for _, receipt := range r.redirectOwnedRoutes.routes {
		if receipt.Table != r.redirectRouteTableIndex {
			retained = append(retained, receipt)
			continue
		}
		if slices.ContainsFunc(live, func(route netlink.Route) bool { return redirectReceiptMatchesLive(receipt, route) }) {
			currentRoutes = append(currentRoutes, receipt)
			retained = append(retained, receipt)
		} else if slices.ContainsFunc(live, func(route netlink.Route) bool { return redirectRouteSlotMatches(receipt, route) }) {
			// A changed selector is not proof of deletion. Preserve all debt
			// and stop before writes rather than adopt or overwrite it.
			return E.New("redirect route identity is ambiguous; cleanup receipt retained")
		}
	}
	clear(r.redirectOwnedRoutes.routes[len(retained):])
	r.redirectOwnedRoutes.routes = retained
	routesToAdd, routesToDelete := calculateRedirectRouteChanges(
		r.redirectRouteTableIndex,
		redirectInterfaces,
		currentRoutes,
		r.enableIPv4,
		r.enableIPv6,
	)
	for index := range routesToDelete {
		route := &routesToDelete[index]
		normalized := normalizeRedirectReceipt(*route)
		err = remove(&normalized)
		if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
			return E.Cause(err, "delete redirect route ", route)
		}
		for i := range r.redirectOwnedRoutes.routes {
			if r.redirectOwnedRoutes.routes[i].Equal(*route) {
				r.redirectOwnedRoutes.routes = slices.Delete(r.redirectOwnedRoutes.routes, i, i+1)
				break
			}
		}
	}
	for index := range routesToAdd {
		route := &routesToAdd[index]
		err = r.addOwnedRedirectRoute(route, add)
		if err != nil {
			return E.Cause(err, "append redirect route ", route)
		}
	}
	return nil
}

// Linux reports IPv6 local routes with global scope and fills an omitted
// metric with IP6_RT_PRIO_USER (1024). Match the kernel selectors for both
// readback and deletion; other configured selectors still distinguish routes.
func normalizeRedirectReceipt(receipt netlink.Route) netlink.Route {
	if receipt.Dst != nil && receipt.Dst.IP.To4() == nil {
		if receipt.Priority == 0 {
			receipt.Priority = 1024
		}
		if receipt.Type == unix.RTN_LOCAL && receipt.Scope == netlink.SCOPE_HOST {
			receipt.Scope = netlink.SCOPE_UNIVERSE
		}
	}
	return receipt
}

func redirectReceiptMatchesLive(receipt, live netlink.Route) bool {
	receipt = normalizeRedirectReceipt(receipt)
	const dynamicFlags = unix.RTNH_F_DEAD | unix.RTNH_F_LINKDOWN
	receipt.Flags &^= dynamicFlags
	live.Flags &^= dynamicFlags
	return receipt.Equal(live)
}

func redirectRouteSlotMatches(receipt, live netlink.Route) bool {
	if receipt.Table != live.Table || receipt.LinkIndex != live.LinkIndex || receipt.Dst == nil || live.Dst == nil {
		return false
	}
	return receipt.Dst.String() == live.Dst.String()
}

func calculateRedirectRouteChanges(
	tableIndex int,
	redirectInterfaces []control.Interface,
	currentRoutes []netlink.Route,
	enableIPv4 bool,
	enableIPv6 bool,
) (routesToAdd []netlink.Route, routesToDelete []netlink.Route) {
	desiredRoutes := make(map[redirectRouteKey]struct{}, len(redirectInterfaces)*2)
	for _, iface := range redirectInterfaces {
		hasIPv4Address, hasIPv6Address := redirectRouteAddressFamilies(iface)
		if enableIPv4 && hasIPv4Address {
			desiredRoutes[redirectRouteKey{linkIndex: iface.Index, family: unix.AF_INET}] = struct{}{}
		}
		if enableIPv6 && hasIPv6Address {
			desiredRoutes[redirectRouteKey{linkIndex: iface.Index, family: unix.AF_INET6}] = struct{}{}
		}
	}
	for _, route := range currentRoutes {
		key, isRedirectRoute := redirectRouteKeyFromRoute(route)
		if !isRedirectRoute {
			continue
		}
		if _, desired := desiredRoutes[key]; desired {
			delete(desiredRoutes, key)
			continue
		}
		routesToDelete = append(routesToDelete, route)
	}
	for key := range desiredRoutes {
		routesToAdd = append(routesToAdd, newRedirectRoute(tableIndex, key))
	}
	return
}

func newRedirectRoute(tableIndex int, key redirectRouteKey) netlink.Route {
	destination := net.IPv6loopback
	if key.family == unix.AF_INET {
		destination = net.IPv4(127, 0, 0, 1)
	}
	priority := 0
	if key.family == unix.AF_INET6 {
		priority = 1024
	} // IP6_RT_PRIO_USER
	return netlink.Route{
		Priority:  priority,
		LinkIndex: key.linkIndex,
		Dst:       netlink.NewIPNet(destination),
		Table:     tableIndex,
		Type:      unix.RTN_LOCAL,
		Protocol:  unix.RTPROT_BOOT,
		Scope:     netlink.SCOPE_HOST,
	}
}

func redirectRouteKeyFromRoute(route netlink.Route) (redirectRouteKey, bool) {
	if redirectRouteDestinationMatches(route.Dst, net.IPv4(127, 0, 0, 1), 32) {
		return redirectRouteKey{linkIndex: route.LinkIndex, family: unix.AF_INET}, true
	}
	if redirectRouteDestinationMatches(route.Dst, net.IPv6loopback, 128) {
		return redirectRouteKey{linkIndex: route.LinkIndex, family: unix.AF_INET6}, true
	}
	return redirectRouteKey{}, false
}

func redirectRouteDestinationMatches(destination *net.IPNet, address net.IP, prefixBits int) bool {
	if destination == nil || !destination.IP.Equal(address) {
		return false
	}
	ones, bits := destination.Mask.Size()
	return ones == prefixBits && bits == prefixBits
}

func flushRouteTable(tableIndex int) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		flushRouteTableFamily(tableIndex, family)
	}
}

func flushRouteTableFamily(tableIndex int, family int) {
	routes, _ := netlink.RouteListFiltered(family,
		&netlink.Route{Table: tableIndex},
		netlink.RT_FILTER_TABLE)
	for index := range routes {
		route := &routes[index]
		if route.Dst == nil {
			route.Dst = defaultDestination(family)
		}
		_ = netlink.RouteDel(route)
	}
}

func (r *autoRedirect) cleanupStaleRouteRules(priority int, mark uint32) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := netlink.RuleListFiltered(family,
			&netlink.Rule{Priority: priority},
			netlink.RT_FILTER_PRIORITY)
		if err != nil {
			continue
		}
		for index := range rules {
			staleRule := &rules[index]
			if staleRule.Mark != mark || staleRule.Table <= 255 {
				continue
			}
			flushRouteTable(staleRule.Table)
			_ = netlink.RuleDel(staleRule)
		}
	}
}

func defaultDestination(family int) *net.IPNet {
	if family == unix.AF_INET6 {
		return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
}
