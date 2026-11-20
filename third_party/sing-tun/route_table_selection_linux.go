//go:build linux

package tun

import (
	"fmt"
	"math/rand"
	"slices"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// Bound random retries, including reserved/excluded/duplicate draws. This bounds
// query count, not the duration of an individual netlink operation. Discovery is
// not a reservation: callers must still handle concurrent RouteAdd conflicts.
const routeTableSelectionAttempts = 256

func chooseRouteTableIndex(excludedIndexes ...int) (int, error) {
	return chooseRouteTableIndexWith(rand.Uint32, routeTableOccupied, excludedIndexes...)
}

func chooseRouteTableIndexWith(next func() uint32, occupied func(int) (bool, error), excludedIndexes ...int) (int, error) {
	seen := make(map[int]struct{})
	for attempt := 0; attempt < routeTableSelectionAttempts; attempt++ {
		tableIndex := int(next() & 0x7fffffff)
		if tableIndex <= 255 || slices.Contains(excludedIndexes, tableIndex) {
			continue
		}
		if _, found := seen[tableIndex]; found {
			continue
		}
		seen[tableIndex] = struct{}{}
		used, err := occupied(tableIndex)
		if err != nil {
			return 0, fmt.Errorf("query route table %d: %w", tableIndex, err)
		}
		if !used {
			return tableIndex, nil
		}
	}
	return 0, fmt.Errorf("no available route table after %d candidate attempts", routeTableSelectionAttempts)
}

func routeTableOccupied(tableIndex int) (bool, error) {
	return routeTableOccupiedWith(tableIndex, netlink.RouteListFiltered)
}

func routeTableOccupiedWith(tableIndex int, list func(int, *netlink.Route, uint64) ([]netlink.Route, error)) (bool, error) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := list(family, &netlink.Route{Table: tableIndex}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return false, fmt.Errorf("family %d: %w", family, err)
		}
		if len(routes) > 0 {
			return true, nil
		}
	}
	return false, nil
}
