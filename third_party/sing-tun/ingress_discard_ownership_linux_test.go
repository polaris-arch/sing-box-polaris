//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func ingressTestValue(index int) (value [8]byte) {
	binary.NativeEndian.PutUint32(value[:4], uint32(index))
	binary.NativeEndian.PutUint32(value[4:], uint32(index))
	return
}
func TestIngressDeleteSuccessOnlyReceipt(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.1")
	for _, result := range []error{nil, unix.ENOENT, unix.EPERM} {
		receipts := make(map[netip.Addr]ingressDiscardReceipt)
		ops := ingressDiscardOps{lookup: func(netip.Addr) ([8]byte, error) { return ingressTestValue(7), nil }, remove: func(netip.Addr) error { return result }}
		err := removeIngressDiscard(receipts, address, 4, 7, ops)
		if result == nil && (err != nil || len(receipts) != 1) {
			t.Fatal("successful delete missing receipt", err)
		}
		if result != nil && len(receipts) != 0 {
			t.Fatal("failed delete recorded")
		}
		if result == unix.EPERM && err == nil {
			t.Fatal("failure hidden")
		}
	}
}
func TestIngressNoDeleteOnLookupFailureOrForeignValue(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.1")
	for _, result := range []error{nil, unix.ENOENT, unix.EPERM} {
		receipts := make(map[netip.Addr]ingressDiscardReceipt)
		deletes := 0
		ops := ingressDiscardOps{lookup: func(netip.Addr) ([8]byte, error) { return ingressTestValue(8), result }, remove: func(netip.Addr) error { deletes++; return nil }}
		err := removeIngressDiscard(receipts, address, 4, 7, ops)
		if deletes != 0 || len(receipts) != 0 {
			t.Fatal("foreign or failed lookup deleted")
		}
		if result == unix.EPERM && err == nil {
			t.Fatal("lookup error hidden")
		}
	}
}
func TestIngressPendingReceiptConflictPreservesDebt(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.1")
	for _, kind := range []string{"map", "interface", "value", "zero"} {
		t.Run(kind, func(t *testing.T) {
			original := ingressDiscardReceipt{4, ingressTestValue(7)}
			receipts := map[netip.Addr]ingressDiscardReceipt{address: original}
			mapID, index, value := uint32(4), 7, ingressTestValue(7)
			switch kind {
			case "map":
				mapID = 5
			case "interface":
				index = 8
			case "value":
				value = ingressTestValue(8)
			case "zero":
				mapID = 0
			}
			deletes := 0
			ops := ingressDiscardOps{lookup: func(netip.Addr) ([8]byte, error) { return value, nil }, remove: func(netip.Addr) error { deletes++; return nil }}
			if err := removeIngressDiscard(receipts, address, mapID, index, ops); err == nil || deletes != 0 || receipts[address] != original {
				t.Fatal("pending debt replaced")
			}
		})
	}
}
func TestIngressRestoreFailureRetainsReceipt(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.1")
	for _, failure := range []error{unix.EEXIST, unix.EPERM} {
		original := ingressDiscardReceipt{4, ingressTestValue(7)}
		receipts := map[netip.Addr]ingressDiscardReceipt{address: original}
		ops := ingressDiscardOps{restore: func(netip.Addr, [8]byte) error { return failure }}
		if err := restoreIngressDiscard(receipts, 4, 7, ops); !errors.Is(err, failure) || receipts[address] != original {
			t.Fatal("restore failure lost debt", err)
		}
		ops.restore = func(netip.Addr, [8]byte) error { return nil }
		if err := restoreIngressDiscard(receipts, 4, 7, ops); err != nil || len(receipts) != 0 {
			t.Fatal("retry failed", err)
		}
	}
}
func TestIngressRestoreIdentityMismatchNeverWrites(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.1")
	for _, kind := range []string{"map", "interface", "second-slot", "zero"} {
		t.Run(kind, func(t *testing.T) {
			value := ingressTestValue(7)
			mapID, index := uint32(4), 7
			switch kind {
			case "map":
				mapID = 5
			case "interface":
				index = 8
			case "second-slot":
				binary.NativeEndian.PutUint32(value[4:], 8)
			case "zero":
				mapID = 0
			}
			receipts := map[netip.Addr]ingressDiscardReceipt{address: {4, value}}
			writes := 0
			ops := ingressDiscardOps{restore: func(netip.Addr, [8]byte) error { writes++; return nil }}
			if err := restoreIngressDiscard(receipts, mapID, index, ops); err == nil || writes != 0 || len(receipts) != 1 {
				t.Fatal("identity mismatch restored")
			}
		})
	}
}
func TestIngressRestorePartialSuccessOnlyDropsSuccess(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	receipts := map[netip.Addr]ingressDiscardReceipt{a: {4, ingressTestValue(7)}, b: {4, ingressTestValue(7)}}
	ops := ingressDiscardOps{restore: func(address netip.Addr, value [8]byte) error {
		if address == b {
			return unix.EEXIST
		}
		return nil
	}}
	if err := restoreIngressDiscard(receipts, 4, 7, ops); !errors.Is(err, unix.EEXIST) || len(receipts) != 1 {
		t.Fatal("partial recovery incorrect", err)
	}
	if _, ok := receipts[b]; !ok {
		t.Fatal("failed restore debt lost")
	}
}
