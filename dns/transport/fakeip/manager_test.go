package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/log"
)

func TestBoxAllocatorSurvivesBorrowAbortReplacementAndRemoval(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.0/15")
	manager, err := NewManager(context.Background(), log.NewNOPFactory().Logger(), prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	aborted, err := manager.Borrow(prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if manager.started.Load() {
		t.Fatal("candidate Borrow started allocator")
	}
	if err := aborted.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := manager.Borrow(prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	address, err := first.Create("late-first-flow.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	recognition := manager.RecognitionStore()
	if domain, ok := recognition.Lookup(address); !ok || domain != "late-first-flow.example" {
		t.Fatal("transport removal erased recognition")
	}
	replacement, err := manager.Borrow(prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := replacement.Start(); err != nil {
		t.Fatal(err)
	}
	actual, err := replacement.Create("late-first-flow.example", false)
	if err != nil || actual != address {
		t.Fatal("same-range replacement changed allocator identity")
	}
	if err := recognition.Reset(); !errors.Is(err, ErrRecognitionReadOnly) {
		t.Fatal("recognition reset was allowed")
	}
	if _, err := recognition.Create("invalid.example", false); !errors.Is(err, ErrRecognitionReadOnly) {
		t.Fatal("recognition allocated an address")
	}
}

func TestRangeReplacementFailsWithoutClearingExistingMappings(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.0/15")
	manager, err := NewManager(context.Background(), log.NewNOPFactory().Logger(), prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	first, err := manager.Borrow(prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	address, err := first.Create("retained.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Borrow(netip.MustParsePrefix("198.18.0.0/16"), netip.Prefix{}); !errors.Is(err, ErrMigrationRequired) {
		t.Fatal("overlapping range silently created an independent allocator")
	}
	if domain, ok := manager.RecognitionStore().Lookup(address); !ok || domain != "retained.example" {
		t.Fatal("failed prepare mutated live recognition")
	}
}

func TestStableManagerPreservesExistingPoolReuseCapacity(t *testing.T) {
	// /30 has the existing single usable address (.2). This test records the
	// baseline reuse behavior; it does not promise TTL-safe reuse or infinitely
	// late first-flow lookup after the address has been reassigned.
	prefix := netip.MustParsePrefix("198.18.0.0/30")
	manager, err := NewManager(context.Background(), log.NewNOPFactory().Logger(), prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	store, err := manager.Borrow(prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Start(); err != nil {
		t.Fatal(err)
	}
	first, err := store.Create("first.example", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create("second.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("existing cursor capacity/reuse semantics changed")
	}
	if domain, _ := manager.RecognitionStore().Lookup(first); domain != "second.example" {
		t.Fatal("recognition diverged from authoritative allocator")
	}
}
