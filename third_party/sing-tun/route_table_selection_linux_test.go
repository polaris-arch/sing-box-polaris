//go:build linux

package tun

import (
	"errors"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
	"testing"
)

func TestRouteTableSelectionSkipsInvalidAndRepeatedCandidates(t *testing.T) {
	values := []uint32{0, 255, 256, 300, 300, 0x8000012d}
	draws, queries := 0, 0
	table, err := chooseRouteTableIndexWith(func() uint32 { v := values[draws]; draws++; return v }, func(i int) (bool, error) { queries++; return i == 300, nil }, 256)
	if err != nil || table != 301 || queries != 2 || draws != len(values) {
		t.Fatalf("table=%d err=%v queries=%d draws=%d", table, err, queries, draws)
	}
}
func TestRouteTableSelectionFailsClosed(t *testing.T) {
	want := errors.New("denied")
	draws := 0
	table, err := chooseRouteTableIndexWith(func() uint32 { draws++; return 300 }, func(int) (bool, error) { return false, want })
	if table != 0 || !errors.Is(err, want) || draws != 1 {
		t.Fatalf("table=%d err=%v draws=%d", table, err, draws)
	}
}
func TestRouteTableSelectionBounded(t *testing.T) {
	for _, mode := range []string{"reserved", "duplicate", "occupied"} {
		t.Run(mode, func(t *testing.T) {
			draws, queries := 0, 0
			table, err := chooseRouteTableIndexWith(func() uint32 {
				draws++
				switch mode {
				case "reserved":
					return 1
				case "duplicate":
					return 300
				default:
					return uint32(300 + draws)
				}
			}, func(int) (bool, error) { queries++; return true, nil })
			if err == nil || table != 0 || draws != routeTableSelectionAttempts {
				t.Fatalf("table=%d err=%v draws=%d", table, err, draws)
			}
			want := routeTableSelectionAttempts
			if mode == "reserved" {
				want = 0
			}
			if mode == "duplicate" {
				want = 1
			}
			if queries != want {
				t.Fatalf("queries=%d want=%d", queries, want)
			}
		})
	}
}
func TestRouteTableOccupiedQueriesBothFamiliesAndPropagatesFailure(t *testing.T) {
	for _, failed := range []int{0, unix.AF_INET, unix.AF_INET6} {
		want := errors.New("query failed")
		calls := 0
		used, err := routeTableOccupiedWith(777, func(family int, r *netlink.Route, filter uint64) ([]netlink.Route, error) {
			calls++
			if r.Table != 777 || filter != netlink.RT_FILTER_TABLE {
				t.Fatal("wrong selector")
			}
			if family == failed {
				return nil, want
			}
			return nil, nil
		})
		if used {
			t.Fatal("empty query marked occupied")
		}
		if failed == 0 {
			if err != nil || calls != 2 {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
		} else if !errors.Is(err, want) {
			t.Fatalf("missing error: %v", err)
		}
	}
}
func TestRouteTableOccupiedIPv6AndEarlyIPv4(t *testing.T) {
	for _, occupiedFamily := range []int{unix.AF_INET, unix.AF_INET6} {
		calls := 0
		used, err := routeTableOccupiedWith(888, func(family int, _ *netlink.Route, _ uint64) ([]netlink.Route, error) {
			calls++
			if family == occupiedFamily {
				return []netlink.Route{{Table: 888}}, nil
			}
			return nil, nil
		})
		if !used || err != nil {
			t.Fatalf("used=%v err=%v", used, err)
		}
		if occupiedFamily == unix.AF_INET && calls != 1 {
			t.Fatal("unnecessary query after occupied table")
		}
	}
}
