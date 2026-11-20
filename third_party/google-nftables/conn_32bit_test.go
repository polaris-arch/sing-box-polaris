package nftables

import (
	"math"
	"testing"
)

func TestTransactionIDAllocationUint32Boundary(t *testing.T) {
	cc := &Conn{allocatedIDs: math.MaxUint32 - 1, lastID: math.MaxUint32 - 1}
	if got := cc.allocateTransactionID(); got != math.MaxUint32 {
		t.Fatalf("last allowed ID=%d", got)
	}
	defer func() {
		const expected = "trying to allocate more than 4294967295 IDs in a single nftables transaction"
		if got := recover(); got != expected {
			t.Fatalf("panic=%v, want %q", got, expected)
		}
		if cc.allocatedIDs != math.MaxUint32 || cc.lastID != math.MaxUint32 {
			t.Fatal("rejected allocation changed counters")
		}
	}()
	cc.allocateTransactionID()
}

func TestTransactionIDWrapRemainsNonzero(t *testing.T) {
	cc := &Conn{lastID: math.MaxUint32}
	if got := cc.allocateTransactionID(); got != 1 || cc.allocatedIDs != 1 {
		t.Fatalf("wrapped ID=%d allocations=%d", got, cc.allocatedIDs)
	}
}
