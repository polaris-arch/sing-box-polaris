package fakeip

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

type fixedInitialCacheFixture struct {
	adapter.CacheFile
	storage                   *MemoryStorage
	metadata                  *adapter.FakeIPMetadata
	opened                    bool
	snapshots, resets, writes int
	failure                   error
}

func (f *fixedInitialCacheFixture) StoreFakeIP() bool { return true }
func (f *fixedInitialCacheFixture) FakeIPMetadata() *adapter.FakeIPMetadata {
	panic("lossy metadata read must not be used during initial preparation")
}

func (f *fixedInitialCacheFixture) FakeIPSaveMetadata(metadata *adapter.FakeIPMetadata) error {
	f.writes++
	copy := *metadata
	f.metadata = &copy
	return nil
}

func (f *fixedInitialCacheFixture) FakeIPStore(address netip.Addr, domain string) error {
	return f.storage.FakeIPStore(address, domain)
}

func (f *fixedInitialCacheFixture) FakeIPStoreAsync(address netip.Addr, domain string, l logger.Logger) {
	f.storage.FakeIPStoreAsync(address, domain, l)
}

func (f *fixedInitialCacheFixture) FakeIPLoad(address netip.Addr) (string, bool) {
	return f.storage.FakeIPLoad(address)
}

func (f *fixedInitialCacheFixture) FakeIPLoadDomain(domain string, ipv6 bool) (netip.Addr, bool) {
	return f.storage.FakeIPLoadDomain(domain, ipv6)
}

func (f *fixedInitialCacheFixture) FakeIPReset() error {
	f.resets++
	return errors.New("unexpected reset")
}

func (f *fixedInitialCacheFixture) SnapshotFakeIP(context.Context) (adapter.FakeIPStorageSnapshot, error) {
	f.snapshots++
	if f.failure != nil {
		return adapter.FakeIPStorageSnapshot{}, f.failure
	}
	if !f.opened {
		return adapter.FakeIPStorageSnapshot{}, errors.New("fixture physical cache not open")
	}
	result := adapter.FakeIPStorageSnapshot{Mappings: make(map[netip.Addr]string)}
	if f.metadata != nil {
		copy := *f.metadata
		result.Metadata = &copy
	}
	f.storage.addressAccess.RLock()
	maps.Copy(result.Mappings, f.storage.addressCache)
	f.storage.addressAccess.RUnlock()
	return result, nil
}

func fixedInitialManager(t *testing.T, cache *fixedInitialCacheFixture) *Manager {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.CacheFile](ctx, cache)
	manager := NewEmptyManager(ctx, log.NewNOPFactory().Logger())
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	return manager
}

func TestInitialPersistentPreparationWaitsForActualCache(t *testing.T) {
	cache := &fixedInitialCacheFixture{storage: NewMemoryStorage()}
	manager := fixedInitialManager(t, cache)
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	candidate, err := manager.PrepareInitialPersistentRanges(context.Background(), prefix, netip.Prefix{}, cache)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { candidate.Abort(); candidate.ActivatePersistence() }()
	if cache.snapshots != 0 || candidate.namespace.store.storage != nil {
		t.Fatal("constructor touched cache or substituted memory")
	}
	if _, _, err = candidate.PrepareCommit(); !errors.Is(err, ErrInitialPersistentBindingRequired) {
		t.Fatal("unbound persistent candidate committed", err)
	}
	if err = candidate.InitializePersistentStorage(context.Background()); err == nil {
		t.Fatal("unopened cache accepted")
	}
	cache.opened = true
	if err = candidate.InitializePersistentStorage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cache.resets != 0 || cache.writes != 0 {
		t.Fatal("initialization mutated persistent data")
	}
	commit, _, err := candidate.PrepareCommit()
	if err != nil {
		t.Fatal(err)
	}
	commit.Publish()
	candidate.ActivatePersistence()
	store, err := manager.Borrow(prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	address, err := store.Create("first.example", false)
	if err != nil || address != netip.MustParseAddr("198.18.0.2") {
		t.Fatal("baseline first cursor changed", address, err)
	}
	if cache.resets != 0 || cache.writes != 1 {
		t.Fatal("baseline cursor reservation changed", cache.resets, cache.writes)
	}
}

func TestInitialPersistentResumeAndDailyReusePreserveAllocator(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	cache := &fixedInitialCacheFixture{storage: NewMemoryStorage(), opened: true, metadata: &adapter.FakeIPMetadata{Inet4Range: prefix, Inet4Current: netip.MustParseAddr("198.18.0.5")}}
	saved := netip.MustParseAddr("198.18.0.2")
	_ = cache.storage.FakeIPStore(saved, "saved.example")
	manager := fixedInitialManager(t, cache)
	candidate, err := manager.PrepareInitialPersistentRanges(context.Background(), prefix, netip.Prefix{}, cache)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { candidate.Abort(); candidate.ActivatePersistence() }()
	if err = candidate.InitializePersistentStorage(context.Background()); err != nil {
		t.Fatal(err)
	}
	commit, _, err := candidate.PrepareCommit()
	if err != nil {
		t.Fatal(err)
	}
	commit.Publish()
	candidate.ActivatePersistence()
	original := manager.store
	daily, err := manager.PrepareRanges(context.Background(), prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { daily.Abort(); daily.ActivatePersistence() }()
	if daily.namespace.store != original || daily.namespace != manager.active {
		t.Fatal("same-range edit recreated allocator")
	}
	if cache.resets != 0 || cache.writes != 0 || manager.store.inet4Current != netip.MustParseAddr("198.18.0.5") {
		t.Fatal("daily preparation changed cursor")
	}
	store, err := manager.Borrow(prefix, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	address, err := store.Create("saved.example", false)
	if err != nil || address != saved {
		t.Fatal("persisted mapping changed", address, err)
	}
	address, err = store.Create("next.example", false)
	if err != nil || address != netip.MustParseAddr("198.18.0.6") {
		t.Fatal("persisted cursor did not resume", address, err)
	}
}

func TestInitialPersistentInvalidMetadataNeverResets(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	for _, metadata := range []*adapter.FakeIPMetadata{
		{Inet4Range: netip.MustParsePrefix("198.19.0.0/29"), Inet4Current: netip.MustParseAddr("198.19.0.1")},
		{Inet4Range: prefix, Inet4Current: netip.MustParseAddr("198.18.0.7")},
	} {
		cache := &fixedInitialCacheFixture{storage: NewMemoryStorage(), opened: true, metadata: metadata}
		manager := fixedInitialManager(t, cache)
		candidate, err := manager.PrepareInitialPersistentRanges(context.Background(), prefix, netip.Prefix{}, cache)
		if err != nil {
			t.Fatal(err)
		}
		if err = candidate.InitializePersistentStorage(context.Background()); !errors.Is(err, ErrInitialPersistentMetadata) {
			t.Fatal("invalid metadata accepted", err)
		}
		candidate.Abort()
		candidate.ActivatePersistence()
		if cache.resets != 0 || cache.writes != 0 || candidate.namespace.store.storage != nil {
			t.Fatal("failed initialization changed storage")
		}
	}
}

func TestOrdinaryPrepareNeverReadsUnopenedPersistentCache(t *testing.T) {
	cache := &fixedInitialCacheFixture{storage: NewMemoryStorage()}
	manager := fixedInitialManager(t, cache)
	if _, err := manager.PrepareRanges(context.Background(), netip.MustParsePrefix("198.18.0.0/29"), netip.Prefix{}); !errors.Is(err, ErrInitialPersistentBindingRequired) {
		t.Fatal(err)
	}
	if cache.snapshots != 0 || cache.resets != 0 || cache.writes != 0 {
		t.Fatal("ordinary prepare touched unopened persistent cache")
	}
}

// Reuse the existing storage/transaction fixtures through the real initial
// cache interface. Only the legacy snapshot method needs disambiguation.
// These model tests do not claim physical database durability coverage.
type recoveredInitialCacheFixture struct {
	*fixedInitialCacheFixture
	*runtimeFixtureBackend
}

func (f *recoveredInitialCacheFixture) SnapshotFakeIP(ctx context.Context) (adapter.FakeIPStorageSnapshot, error) {
	return f.fixedInitialCacheFixture.SnapshotFakeIP(ctx)
}

func TestRecoveredSelectedBatchMappingsRespectProtectedAndSupersededAuthority(t *testing.T) {
	for _, startup := range []string{"initial-binding", "persistent-startup"} {
		t.Run(startup, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(100, 0)
			prefix := netip.MustParsePrefix("198.18.0.0/29")
			backend := fixtureBackend("selected-batch")
			resolver := fixtureResolver(backend)
			options := fixtureOptions(backend, resolver, "original-selected")
			options.Backend = backend
			previous := fixtureEmptyManager(t)
			previous.now = func() time.Time { return now }
			candidate, err := previous.PreparePersistentRanges(ctx, prefix, netip.Prefix{}, options)
			if err != nil {
				t.Fatal(err)
			}
			sourceReusePublishDurable(t, candidate)
			issued := make(map[string]netip.Addr)
			for _, domain := range []string{"protected.example", "superseded.example"} {
				address, err := previous.create(domain, false)
				if err != nil {
					t.Fatal(err)
				}
				answer, err := previous.ProtectAnswer(fakeAnswer(address, domain, 600))
				if err != nil {
					t.Fatal(err)
				}
				answer.Delivered(now)
				issued[domain] = address
			}
			if err := candidate.AcknowledgePersistence(ctx, options.EffectiveConfigurationID); err != nil {
				t.Fatal(err)
			}
			backend.access.Lock()
			observed := backend.observed
			backend.access.Unlock()
			batch, err := previous.create("batch.example", false)
			if err != nil {
				t.Fatal(err)
			}
			answer, err := previous.ProtectAnswer(fakeAnswer(batch, "batch.example", 600))
			if err != nil {
				t.Fatal(err)
			}
			answer.Delivered(now)
			backend.access.Lock()
			if backend.observed != observed {
				backend.access.Unlock()
				t.Fatal("acknowledged unchanged allocation left the batch path")
			}
			backend.access.Unlock()
			previous.mappingAccess.Lock()
			handle := previous.active.durable.handle
			cursor := previous.store.inet4Current
			previous.mappingAccess.Unlock()
			if err := previous.Close(); err != nil {
				t.Fatal(err)
			}
			image, err := handle.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var veto []adapter.FakeIPRuntimeAnswer
			for _, record := range image.Answers {
				if record.Address == issued["superseded.example"] {
					veto = append(veto, record)
				}
			}
			if len(veto) != 1 {
				t.Fatal("actual delivered identity did not reach the journal", veto)
			}
			if err := handle.Invalidate(ctx, veto); err != nil {
				t.Fatal(err)
			}
			cache := &recoveredInitialCacheFixture{
				fixedInitialCacheFixture: &fixedInitialCacheFixture{storage: NewMemoryStorage(), opened: true},
				runtimeFixtureBackend:    backend,
			}
			coldContext := service.ContextWithDefaultRegistry(ctx)
			service.MustRegister[adapter.CacheFile](coldContext, cache)
			cold := NewEmptyManager(coldContext, log.NewNOPFactory().Logger())
			cold.now = func() time.Time { return now }
			if err := cold.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := cold.Close(); err != nil {
					t.Error(err)
				}
			})
			if err := cold.RecoverPersistent(ctx, backend, resolver, options.EffectiveConfigurationID, backend); err != nil {
				t.Fatal(err)
			}
			cold.mappingAccess.Lock()
			protected := cold.authority[issued["protected.example"]]
			cold.mappingAccess.Unlock()
			if protected.domain != "protected.example" || protected.revision == 0 {
				t.Fatal("real delivered certificate was not recovered", protected)
			}
			if startup == "initial-binding" {
				for _, abort := range []bool{true, false} {
					restart, err := cold.PrepareInitialPersistentRanges(ctx, prefix, netip.Prefix{}, cache)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { restart.Abort(); restart.ActivatePersistence() })
					if err := restart.InitializePersistentStorage(ctx); err != nil {
						t.Fatal(err)
					}
					fence, _, err := restart.PrepareCommit()
					if err != nil {
						t.Fatal(err)
					}
					if abort {
						fence.Abort()
						restart.ActivatePersistence()
						if _, ok := cold.RecognitionStore().Lookup(batch); ok {
							t.Fatal("aborted initial binding exposed a selected mapping")
						}
					} else {
						fence.Publish()
						restart.ActivatePersistence()
					}
				}
			} else {
				options.TransactionID = "cold-selected"
				restart, err := cold.PreparePersistentRanges(ctx, prefix, netip.Prefix{}, options)
				if err != nil {
					t.Fatal(err)
				}
				sourceReusePublishDurable(t, restart)
			}
			if domain, ok := cold.RecognitionStore().Lookup(batch); !ok || domain != "batch.example" {
				t.Fatal("selected ordinary mapping was not recovered", domain, ok)
			}
			if _, ok := cold.RecognitionStore().Lookup(issued["superseded.example"]); ok {
				t.Fatal("selected allocator resurrected an actually invalidated identity")
			}
			cold.mappingAccess.Lock()
			retained := cold.authority[issued["protected.example"]]
			cold.mappingAccess.Unlock()
			if retained != protected {
				t.Fatal("selected allocator replaced protected namespace/revision custody", retained, protected)
			}
			store, err := cold.Borrow(prefix, netip.Prefix{})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if reused, err := store.Create("batch.example", false); err != nil || reused != batch {
				t.Fatal("same-domain mapping did not retain its actual address", reused, err)
			}
			next, err := store.Create("next.example", false)
			if err != nil || next != cursor.Next() {
				t.Fatal("selected allocator cursor did not resume", next, cursor, err)
			}
			if domain, ok := cold.RecognitionStore().Lookup(next); !ok || domain != "next.example" {
				t.Fatal("resumed allocation was not authoritative", domain, ok)
			}
		})
	}
}
