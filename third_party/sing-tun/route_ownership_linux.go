package tun

import (
	"errors"
	"fmt"
	"net"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// Only successful adds establish ownership. Regenerated desired routes and
// EEXIST are not proof that this instance installed a route. Callers serialize
// this state with NativeTun.routeAccess. Identical external replacement cannot
// be distinguished by the kernel selector and remains outside this guarantee.
type ownedLinuxRoutes struct {
	routes []netlink.Route
	closed bool
}

// The production builder emits Dst, Gw, LinkIndex and Table. Copy its mutable
// IP storage so a later options update cannot change a cleanup receipt.
func cloneOwnedRoute(route netlink.Route) netlink.Route {
	if route.Dst != nil {
		route.Dst = &net.IPNet{IP: append(net.IP(nil), route.Dst.IP...), Mask: append(net.IPMask(nil), route.Dst.Mask...)}
	}
	route.Gw = append(net.IP(nil), route.Gw...)
	return route
}

func (o *ownedLinuxRoutes) install(routes []netlink.Route, add func(*netlink.Route) error) error {
	if o.closed {
		return errors.New("routing route owner is closed")
	}
	if len(o.routes) != 0 {
		return errors.New("previous owned routes have not been removed")
	}
	for i := range routes {
		route := cloneOwnedRoute(routes[i])
		if err := add(&route); err != nil {
			return fmt.Errorf("add route %d/%d: %w", i, len(routes), err)
		}
		o.routes = append(o.routes, route)
	}
	return nil
}

func (o *ownedLinuxRoutes) clear(remove func(*netlink.Route) error) error {
	var failures []error
	remaining := o.routes[:0]
	for _, receipt := range o.routes {
		route := cloneOwnedRoute(receipt)
		err := remove(&route)
		if err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			continue
		}
		remaining = append(remaining, receipt)
		failures = append(failures, fmt.Errorf("remove owned route table %d link %d: %w", receipt.Table, receipt.LinkIndex, err))
	}
	clear(o.routes[len(remaining):])
	o.routes = remaining
	return errors.Join(failures...)
}

func (o *ownedLinuxRoutes) replace(build func() ([]netlink.Route, error), add, remove func(*netlink.Route) error) error {
	if o.closed {
		return errors.New("routing route owner is closed")
	}
	routes, err := build()
	if err != nil {
		return err
	}
	if err := o.clear(remove); err != nil {
		return err
	}
	if err := o.install(routes, add); err != nil {
		return errors.Join(err, o.clear(remove))
	}
	return nil
}
