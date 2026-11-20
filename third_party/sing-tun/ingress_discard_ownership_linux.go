//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

type ingressDiscardReceipt struct {
	mapID uint32
	value [8]byte
}
type ingressDiscardOps struct {
	lookup  func(netip.Addr) ([8]byte, error)
	remove  func(netip.Addr) error
	restore func(netip.Addr, [8]byte) error
}

func ingressValueMatches(value [8]byte, ifindex int) bool {
	return ifindex > 0 && int(binary.NativeEndian.Uint32(value[:4])) == ifindex && int(binary.NativeEndian.Uint32(value[4:])) == ifindex
}

// Serialized by androidVPNServiceRuleAccess. Lookup and delete are NOT atomic:
// another writer can change the value between them. This receipt only records
// that our delete succeeded, not that the deleted value was independently proved.
func removeIngressDiscard(receipts map[netip.Addr]ingressDiscardReceipt, address netip.Addr, mapID uint32, ifindex int, ops ingressDiscardOps) error {
	if mapID == 0 || ifindex <= 0 {
		return errors.New("invalid ingress discard map/interface identity")
	}
	if previous, ok := receipts[address]; ok && (previous.mapID != mapID || !ingressValueMatches(previous.value, ifindex)) {
		return errors.New("pending ingress discard receipt belongs to another map/interface")
	}
	value, err := ops.lookup(address)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if previous, ok := receipts[address]; ok && previous.value != value {
		return errors.New("pending ingress discard value changed")
	}
	if !ingressValueMatches(value, ifindex) {
		return nil
	}
	if err := ops.remove(address); err != nil {
		// A missing key is not a successful mutation by us and earns no receipt.
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	receipts[address] = ingressDiscardReceipt{mapID, value}
	return nil
}

func restoreIngressDiscard(receipts map[netip.Addr]ingressDiscardReceipt, mapID uint32, ifindex int, ops ingressDiscardOps) error {
	var errs []error
	for address, receipt := range receipts {
		if mapID == 0 || receipt.mapID != mapID || !ingressValueMatches(receipt.value, ifindex) {
			errs = append(errs, fmt.Errorf("restore ingress discard %s: map/interface identity changed", address))
			continue
		}
		// The real operation uses BPF_NOEXIST. Even EEXIST is unresolved debt:
		// neither an existing equal value nor another writer's value is our restore.
		if err := ops.restore(address, receipt.value); err != nil {
			errs = append(errs, fmt.Errorf("restore ingress discard %s: %w", address, err))
			continue
		}
		delete(receipts, address)
	}
	return errors.Join(errs...)
}
