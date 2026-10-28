package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

func prepareMigration(t *testing.T, manager *Manager, prefix string) (*RangeMigration, adapter.FakeIPStore) {
	t.Helper()
	candidate, err := manager.PrepareRanges(context.Background(), netip.MustParsePrefix(prefix), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(candidate.Abort)
	store, err := candidate.Borrow(netip.MustParsePrefix(prefix), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return candidate, store
}

func publishMigration(t *testing.T, candidate *RangeMigration) {
	t.Helper()
	commit, _, err := candidate.PrepareCommit()
	if err != nil {
		t.Fatal(err)
	}
	defer commit.Abort()
	commit.Publish()
	candidate.ActivatePersistence()
}

func TestRetiredRangeKeepsPendingDeliveryTTLAndActiveFirstFlow(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29")
	now := time.Unix(100, 0)
	m.now = func() time.Time { return now }
	old, err := m.Borrow(m.store.inet4Range, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	address, err := old.Create("late.example", false)
	if err != nil {
		t.Fatal(err)
	}
	origin := old.(*borrowedStore).namespace
	answer, err := m.protectAnswer(origin, fakeAnswer(address, "late.example", 600))
	if err != nil {
		t.Fatal(err)
	}
	defer answer.Abort()
	candidate, next := prepareMigration(t, m, "198.19.0.0/29")
	if _, err := next.Create("not-yet.example", false); !errors.Is(err, ErrCandidateNotCommitted) {
		t.Fatal("unpublished namespace answered")
	}
	publishMigration(t, candidate)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if origin.store.storage != nil {
		t.Fatal("retired full allocator cache was not compacted")
	}
	now = now.Add(time.Hour)
	if domain, ok := m.lookup(address); !ok || domain != "late.example" {
		t.Fatal("pending egress lost recognition")
	}
	answer.Delivered(now)
	now = now.Add(599 * time.Second)
	flow, found, err := m.AcquireMapping(address)
	if err != nil || !found {
		t.Fatal("valid late first flow failed", err)
	}
	defer flow.Release()
	now = now.Add(time.Hour)
	if !m.contains(address) {
		t.Fatal("active flow did not retain retired namespace")
	}
	flow.Release()
	if m.contains(address) {
		t.Fatal("expired, unreferenced retired namespace retained forever")
	}
	if _, err := next.Create("new.example", false); err != nil {
		t.Fatal(err)
	}
}

func TestExhaustedOverlapIsPrecommitConflictWithoutLiveMutation(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29")
	now := time.Unix(100, 0)
	m.now = func() time.Time { return now }
	address, err := m.create("held.example", false)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := m.ProtectAnswer(fakeAnswer(address, "held.example", 60))
	if err != nil {
		t.Fatal(err)
	}
	answer.Delivered(now)
	beforeStore, beforeCursor := m.store, m.store.inet4Current
	candidate, _ := prepareMigration(t, m, "198.18.0.0/30")
	commit, impact, err := candidate.PrepareCommit()
	if commit != nil || !errors.Is(err, ErrMigrationConflict) || impact.IPv4.Allocatable != "1" || impact.IPv4.ForeignProtected != 1 {
		t.Fatal("overlap exhaustion was not explicit", impact, err)
	}
	if m.store != beforeStore || m.store.inet4Current != beforeCursor || m.authority != nil {
		t.Fatal("failed prepare changed live allocation")
	}
	if domain, _ := m.lookup(address); domain != "held.example" {
		t.Fatal("failed prepare erased live mapping")
	}
}

func TestSelectedOldNamespaceObserverBlocksCrossNamespaceReuse(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29")
	now := time.Unix(100, 0)
	m.now = func() time.Time { return now }
	old, err := m.Borrow(m.store.inet4Range, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	address, err := old.Create("shared.example", false)
	if err != nil {
		t.Fatal(err)
	}
	candidate, next := prepareMigration(t, m, "198.18.0.0/30")
	publishMigration(t, candidate)
	shared, err := next.Create("shared.example", false)
	if err != nil || shared != address {
		t.Fatal("overlap did not share authoritative identity", err)
	}
	// This answer was produced by the old graph before final TTL processing.
	answer, err := m.protectAnswer(old.(*borrowedStore).namespace, fakeAnswer(address, "shared.example", 60))
	if err != nil {
		t.Fatal(err)
	}
	answer.Delivered(now)
	if _, err := next.Create("different.example", false); !errors.Is(err, ErrAllocationConflict) {
		t.Fatal("new namespace reinterpreted valid old answer", err)
	}
	now = now.Add(time.Minute)
	changed, err := next.Create("different.example", false)
	if err != nil || changed != address {
		t.Fatal("expired foreign guard did not release configured capacity", err)
	}
	nextAnswer, err := m.protectAnswer(next.(*borrowedStore).namespace, fakeAnswer(address, "different.example", 60))
	if err != nil {
		t.Fatal(err)
	}
	nextAnswer.Delivered(now)
	relocated, err := old.Create("shared.example", false)
	if err != nil || relocated == address {
		t.Fatal("retained old graph returned stale domain-cache address", err)
	}
	if domain, _ := m.lookup(address); domain != "different.example" {
		t.Fatal("old allocation stole protected new identity")
	}
}

func TestRetiredNamespaceDropsExpiredRecordsWhileOtherFlowLives(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29")
	now := time.Unix(100, 0)
	m.now = func() time.Time { return now }
	old, err := m.Borrow(m.store.inet4Range, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	short, _ := old.Create("short.example", false)
	long, _ := old.Create("flow.example", false)
	answer, err := m.ProtectAnswer(fakeAnswer(short, "short.example", 1))
	if err != nil {
		t.Fatal(err)
	}
	answer.Delivered(now)
	flow, found, err := m.AcquireMapping(long)
	if err != nil || !found {
		t.Fatal(err)
	}
	defer flow.Release()
	candidate, _ := prepareMigration(t, m, "198.19.0.0/29")
	publishMigration(t, candidate)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, found := m.lookup(short); found {
		t.Fatal("unrelated active flow retained expired mapping")
	}
	if domain, found := m.lookup(long); !found || domain != "flow.example" {
		t.Fatal("live mapping was dropped")
	}
	flow.Release()
}

func TestMigrationPublicationFenceKeepsAllocationOutsidePublish(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29")
	candidate, _ := prepareMigration(t, m, "198.19.0.0/29")
	commit, _, err := candidate.PrepareCommit()
	if err != nil {
		t.Fatal(err)
	}
	defer commit.Abort()
	entered, finished := make(chan struct{}), make(chan struct{})
	go func() { close(entered); _, _ = m.create("fenced.example", false); close(finished) }()
	<-entered
	select {
	case <-finished:
		t.Fatal("allocation crossed held publication fence")
	default:
	}
	commit.Publish()
	candidate.ActivatePersistence()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not release allocation fence")
	}
}

type nonMigratableStorage struct{ adapter.FakeIPStorage }

func TestPersistentBackingRequiresRealMigrationAdapter(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29")
	m.store.storage = nonMigratableStorage{m.store.storage}
	before := m.store
	if _, err := m.PrepareRanges(context.Background(), netip.MustParsePrefix("198.19.0.0/29"), netip.Prefix{}); !errors.Is(err, ErrPersistentMigrationRequired) {
		t.Fatal("persistent range change bypassed migration adapter", err)
	}
	if m.store != before {
		t.Fatal("rejected persistent migration changed store")
	}
}

func TestEmptyBoxAuthorityActivatesFirstRangeOnlyAtPublication(t *testing.T) {
	m := NewEmptyManager(context.Background(), log.NewNOPFactory().Logger())
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if m.store.storage != nil {
		t.Fatal("empty startup initialized/reset fake-IP backing")
	}
	address := netip.MustParseAddr("198.18.0.2")
	if m.contains(address) {
		t.Fatal("empty authority recognized an allocation range")
	}
	if _, found, err := m.AcquireMapping(address); found || err != nil {
		t.Fatal("empty authority changed ordinary routing", err)
	}
	candidate, store := prepareMigration(t, m, "198.18.0.0/29")
	if m.store.storage != nil || m.contains(address) {
		t.Fatal("first prepare changed live authority")
	}
	publishMigration(t, candidate)
	issued, err := store.Create("first-enabled.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if domain, found := m.lookup(issued); !found || domain != "first-enabled.example" {
		t.Fatal("stable authority missed newly enabled fake-IP")
	}
}

func TestMigrationAbortAndStaleCandidateLeaveCurrentAuthority(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29")
	original := m.store
	aborted, abortedStore := prepareMigration(t, m, "198.19.0.0/29")
	fence, _, err := aborted.PrepareCommit()
	if err != nil {
		t.Fatal(err)
	}
	fence.Abort()
	aborted.ActivatePersistence()
	if m.store != original || m.authority != nil {
		t.Fatal("aborted fence published candidate state")
	}
	if _, err := abortedStore.Create("aborted.example", false); !errors.Is(err, ErrCandidateNotCommitted) {
		t.Fatal("aborted candidate issued answer", err)
	}
	stale, _ := prepareMigration(t, m, "198.19.0.0/29")
	winner, _ := prepareMigration(t, m, "198.20.0.0/29")
	publishMigration(t, winner)
	if fence, _, err := stale.PrepareCommit(); fence != nil || !errors.Is(err, ErrMigrationStale) {
		if fence != nil {
			fence.Abort()
			stale.ActivatePersistence()
		}
		t.Fatal("stale range candidate was admitted", err)
	}
	if m.store.inet4Range != netip.MustParsePrefix("198.20.0.0/29") {
		t.Fatal("stale candidate changed current range")
	}
}
