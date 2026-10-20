package fakeip

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing/service"
)

var (
	ErrPersistentMigrationRequired = errors.New("persistent fake-IP namespace migration requires a recovery-capable storage adapter")
	ErrMigrationConflict = errors.New("fake-IP range migration has no collision-safe allocation capacity")
	ErrMigrationStale = errors.New("fake-IP migration candidate is stale or finalized")
	ErrAllocationConflict = errors.New("fake-IP configured pool is exhausted by other retained namespaces")
	ErrNoActiveNamespace = errors.New("Box fake-IP authority has no active allocation namespace")
)

type memoryNamespace struct {
	id uint64
	empty bool
	store *Store
	handles uint64
	operations uint64
	published bool
	retired bool
	aborted bool
	compacted bool
	owned map[netip.Addr]struct{}
	durable *namespacePersistence
}
type authorityEntry struct { domain string; namespace *memoryNamespace; revision uint64 }
type domainKey struct { domain string; ipv6 bool }

// RangeCapacity reports the configured address cardinality, not a new product
// budget. Allocatable excludes the existing network, first and last addresses.
type RangeCapacity struct {
	Range netip.Prefix
	Allocatable string
	ForeignProtected uint64
}
type MigrationImpact struct {
	IPv4 RangeCapacity
	IPv6 RangeCapacity
	RetainedNamespaces int
}
type MigrationConflictError struct { Impact MigrationImpact }
func (e *MigrationConflictError) Error() string { return fmt.Sprintf("%v: IPv4 %d/%s, IPv6 %d/%s protected", ErrMigrationConflict, e.Impact.IPv4.ForeignProtected, e.Impact.IPv4.Allocatable, e.Impact.IPv6.ForeignProtected, e.Impact.IPv6.Allocatable) }
func (e *MigrationConflictError) Unwrap() error { return ErrMigrationConflict }

// RangeMigration owns preparation state only. It cannot issue an answer. The
// coordinator must close its candidate graph handles on abort as usual.
type RangeMigration struct {
	manager *Manager
	namespace *memoryNamespace
	base *memoryNamespace
	permit *AnswerPermit
	state atomic.Uint32 // 0 prepared, 1 fenced, 2 published, 3 aborted
	done func()
	activation sync.Once
	persistent *persistentPreparation
 initial *fixedPersistentPreparation
}

type rangeMigrationContextKey struct{}
func (c *RangeMigration) Context(ctx context.Context) context.Context {
	ctx = ContextWithManager(ctx, c.manager)
	ctx = ContextWithAnswerPermit(ctx, c.permit)
	return context.WithValue(ctx, rangeMigrationContextKey{}, c)
}
func RangeMigrationFromContext(ctx context.Context) (*RangeMigration, bool) {
	candidate, ok := ctx.Value(rangeMigrationContextKey{}).(*RangeMigration)
	return candidate, ok && candidate != nil
}

func validRanges(inet4Range, inet6Range netip.Prefix) error {
	if !inet4Range.IsValid() && !inet6Range.IsValid() { return errors.New("fake-IP requires at least one address range") }
	if inet4Range.IsValid() && (!inet4Range.Addr().Is4() || inet4Range.Bits() > 30) { return errors.New("fake-IP IPv4 range has no allocatable address") }
	if inet6Range.IsValid() && (!inet6Range.Addr().Is6() || inet6Range.Addr().Is4In6() || inet6Range.Bits() > 126) { return errors.New("fake-IP IPv6 range has no allocatable address") }
	return nil
}

func (m *Manager) PrepareRanges(ctx context.Context, inet4Range, inet6Range netip.Prefix) (*RangeMigration, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	if err := validRanges(inet4Range, inet6Range); err != nil { return nil, err }
	done, ok := m.work.Reserve(); if !ok { return nil, lifecycle.ErrStopped }
	if !m.started.Load() { done(); return nil, ErrManagerNotStarted }
	inet4Range, inet6Range = inet4Range.Masked(), inet6Range.Masked()
	m.mappingAccess.Lock()
	m.protection.prune(m.now()); m.collectNamespacesLocked()
	base := m.active
	namespace := base
	if inet4Range != base.store.inet4Range || inet6Range != base.store.inet6Range {
		if !base.empty {
			if _, memory := base.store.storage.(*MemoryStorage); !memory { m.mappingAccess.Unlock(); done(); return nil, ErrPersistentMigrationRequired }
		}
		if m.nextNamespace == ^uint64(0) { m.mappingAccess.Unlock(); done(); return nil, errors.New("fake-IP namespace identity exhausted") }
		m.nextNamespace++
		store := NewStore(m.store.ctx, m.store.logger, inet4Range, inet6Range)
		store.storage = NewMemoryStorage()
		if inet4Range.IsValid() { store.inet4Current = inet4Range.Addr().Next() }
		if inet6Range.IsValid() { store.inet6Current = inet6Range.Addr().Next() }
		if base.empty {
			cache := service.FromContext[adapter.CacheFile](m.store.ctx)
			if cache != nil && cache.StoreFakeIP() { m.mappingAccess.Unlock(); done(); return nil, ErrInitialPersistentBindingRequired }
		}
		if err := ctx.Err(); err != nil { m.mappingAccess.Unlock(); done(); return nil, err }
		namespace = &memoryNamespace{id: m.nextNamespace, store: store, owned: make(map[netip.Addr]struct{})}
		m.namespaces[namespace.id] = namespace
	}
	if err := ctx.Err(); err != nil { if namespace != base { delete(m.namespaces, namespace.id) }; m.mappingAccess.Unlock(); done(); return nil, err }
	candidate := &RangeMigration{manager: m, namespace: namespace, base: base, permit: NewAnswerPermit(), done: done}
	m.mappingAccess.Unlock()
	return candidate, nil
}

func (c *RangeMigration) Borrow(inet4Range, inet6Range netip.Prefix) (adapter.FakeIPStore, error) {
	m := c.manager
	done, ok := m.work.Reserve(); if !ok { return nil, lifecycle.ErrStopped }; defer done()
	m.mappingAccess.Lock(); defer m.mappingAccess.Unlock()
	if c.state.Load() > 1 || c.namespace.aborted { return nil, ErrMigrationStale }
	if inet4Range.Masked() != c.namespace.store.inet4Range || inet6Range.Masked() != c.namespace.store.inet6Range { return nil, ErrMigrationRequired }
	c.namespace.handles++
	return &borrowedStore{manager: m, namespace: c.namespace, permit: c.permit}, nil
}

// RangeCommit holds a short in-memory mutation fence acquired BEFORE the
// coordinator publication lock. Publish has no allocation, I/O or callbacks.
// Call exactly one terminal method; failing to do so retains, rather than
// falsely completing, the candidate and the fence.
type RangeCommit struct {
	candidate *RangeMigration
	state atomic.Uint32
	authority map[netip.Addr]authorityEntry
	domains map[domainKey]netip.Addr
	owned map[*memoryNamespace]map[netip.Addr]struct{}
}

func (c *RangeMigration) PrepareCommit() (*RangeCommit, MigrationImpact, error) {
	if c.persistent != nil { return nil, MigrationImpact{}, errors.New("durable migration requires PrepareDurableCommit before publication") }
	m := c.manager
	m.mappingAccess.Lock()
 if c.initial != nil && !c.initial.ready { m.mappingAccess.Unlock(); return nil, MigrationImpact{}, ErrInitialPersistentBindingRequired }
	if m.work.Sealed() || m.active != c.base || !c.state.CompareAndSwap(0, 1) { m.mappingAccess.Unlock(); return nil, MigrationImpact{}, ErrMigrationStale }
	fail := func(impact MigrationImpact, err error) (*RangeCommit, MigrationImpact, error) { c.state.Store(0); m.mappingAccess.Unlock(); return nil, impact, err }
	m.protection.prune(m.now())
	impact := m.migrationImpactLocked(c.namespace)
	if c.namespace != c.base && (capacityBlocked(impact.IPv4) || capacityBlocked(impact.IPv6)) { return fail(impact, &MigrationConflictError{Impact: impact}) }
	commit := &RangeCommit{candidate: c}
	if c.namespace != c.base && !c.base.empty && m.authority == nil {
		// Snapshot only in-memory storage while mutation is fenced. Preparing
		// this map does not alter live allocation or cache setters.
		commit.authority = make(map[netip.Addr]authorityEntry)
		commit.domains = make(map[domainKey]netip.Addr)
		commit.owned = make(map[*memoryNamespace]map[netip.Addr]struct{})
		for _, namespace := range m.namespaces {
			if !namespace.published { continue }
			storage, memory := namespace.store.storage.(*MemoryStorage)
			if !memory { return fail(impact, ErrPersistentMigrationRequired) }
			owned := make(map[netip.Addr]struct{})
			storage.addressAccess.RLock()
			for address, domain := range storage.addressCache {
				commit.authority[address] = authorityEntry{domain: domain, namespace: namespace}
				commit.domains[domainKey{domain, address.Is6()}] = address
				owned[address] = struct{}{}
			}
			storage.addressAccess.RUnlock()
			commit.owned[namespace] = owned
		}
	}
	for address, entry := range commit.authority { if record := m.protection.current[address]; record != nil && record.current && record.key.domain == entry.domain { entry.revision = record.revision; commit.authority[address] = entry } }
	// Freeze the permit against an outside abort/commit before publication.
	if !c.permit.state.CompareAndSwap(0, 3) { return fail(impact, ErrMigrationStale) }
	return commit, impact, nil
}

func (c *RangeCommit) Publish() {
	expected := uint32(0); if c.candidate.persistent != nil { expected = 3 }
	if !c.state.CompareAndSwap(expected, 1) { return }
	candidate := c.candidate; m := candidate.manager
	if candidate.persistent != nil { candidate.persistent.publishLocked() }
	if c.authority != nil {
		m.authority, m.domains = c.authority, c.domains
		for namespace, owned := range c.owned { namespace.owned = owned }
	}
	if candidate.namespace != m.active {
		m.active.retired = true
		candidate.namespace.published = true
		m.active = candidate.namespace
		m.store = candidate.namespace.store
	}
	candidate.permit.state.Store(1)
	candidate.state.Store(2)
	m.mappingAccess.Unlock()
	// Reclamation is deliberately outside the publication/fence operation.
}
func (c *RangeCommit) Abort() {
	for { state := c.state.Load(); if state != 0 && state != 3 { return }; if c.state.CompareAndSwap(state, 2) { break } }
	c.abortClaimedState()
}
func (c *RangeCommit) abortClaimedState() {
	candidate := c.candidate
	if p := candidate.persistent; p != nil { p.canceled.Store(true) }
	candidate.permit.state.Store(2)
	candidate.state.Store(3)
	if candidate.namespace != candidate.base { candidate.namespace.aborted = true }
	candidate.manager.mappingAccess.Unlock()
}
func (c *RangeMigration) Abort() {
	if p := c.persistent; p != nil {
		// The handed-off fence belongs to the coordinator. Candidate cleanup
		// cannot revoke it behind a concurrent graph publication.
		p.cancel(); if p.commit.Load() != nil { return }
		c.state.CompareAndSwap(0, 3); c.permit.Abort(); c.ActivatePersistence()
		if p.started.CompareAndSwap(false, true) { p.cleanupAborted(); close(p.finished) }
		return
	}
	if !c.state.CompareAndSwap(0, 3) { return }
	c.permit.Abort()
	m := c.manager
	m.mappingAccess.Lock()
	if c.namespace != c.base { c.namespace.aborted = true }
	m.collectNamespacesLocked()
	m.mappingAccess.Unlock()
	c.ActivatePersistence()
}

// ActivatePersistence runs only AFTER the outer publication guards are released.
// It is required for memory fences too, where it releases preparation ownership.
// Duplicate activation and activation before a terminal fence are harmless.
func (c *RangeMigration) ActivatePersistence() {
	state := c.state.Load(); if state != 2 && state != 3 { return }
	c.activation.Do(func() {
		if p := c.persistent; p != nil {
			c.manager.mappingAccess.Lock()
			if c.manager.answerHandoff == p { c.manager.answerHandoff = nil }
			c.manager.mappingAccess.Unlock()
			p.openGate()
		}
		c.done()
	})
}

func allocatable(prefix netip.Prefix) *big.Int {
	if !prefix.IsValid() { return new(big.Int) }
	bits := 128; if prefix.Addr().Is4() { bits = 32 }
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits-prefix.Bits())), big.NewInt(3))
}
func usable(prefix netip.Prefix, address netip.Addr) bool {
	return prefix.IsValid() && prefix.Contains(address) && address != prefix.Addr() && address != prefix.Addr().Next() && address != broadcastAddress(prefix)
}
func capacityBlocked(capacity RangeCapacity) bool {
	if !capacity.Range.IsValid() { return false }
	return allocatable(capacity.Range).Cmp(new(big.Int).SetUint64(capacity.ForeignProtected)) <= 0
}
func (m *Manager) migrationImpactLocked(candidate *memoryNamespace) MigrationImpact {
	impact := MigrationImpact{IPv4: RangeCapacity{Range: candidate.store.inet4Range}, IPv6: RangeCapacity{Range: candidate.store.inet6Range}}
	impact.IPv4.Allocatable = allocatable(impact.IPv4.Range).String()
	impact.IPv6.Allocatable = allocatable(impact.IPv6.Range).String()
	for _, namespace := range m.namespaces { if namespace.published && !namespace.empty && namespace != candidate { impact.RetainedNamespaces++ } }
	for address, records := range m.protection.byAddress {
		blocked := false
		for _, record := range records { if record.key.namespace != candidate.id { blocked = true; break } }
		if !blocked { continue }
		if usable(impact.IPv4.Range, address) { impact.IPv4.ForeignProtected++ }
		if usable(impact.IPv6.Range, address) { impact.IPv6.ForeignProtected++ }
	}
	return impact
}

func (m *Manager) contains(address netip.Addr) bool {
	m.mappingAccess.Lock(); defer m.mappingAccess.Unlock()
	m.protection.prune(m.now()); m.collectNamespacesLocked()
	return m.containsLocked(address)
}
func (m *Manager) containsLocked(address netip.Addr) bool {
	for _, namespace := range m.namespaces { if namespace.published && namespace.store.Contains(address) { return true } }
	return false
}
func (m *Manager) lookupLocked(address netip.Addr) (string, uint64, bool) {
	if m.authority != nil {
		entry, found := m.authority[address]
		if !found { return "", 0, false }
		return entry.domain, entry.namespace.id, true
	}
	if m.active.empty { return "", m.active.id, false }
	domain, found := m.store.Lookup(address)
	return domain, m.active.id, found
}
func (m *Manager) createFor(namespace *memoryNamespace, domain string, ipv6 bool) (netip.Addr, error) {
	done, ok := m.work.Reserve(); if !ok { return netip.Addr{}, lifecycle.ErrStopped }; defer done()
	if !m.started.Load() { return netip.Addr{}, ErrManagerNotStarted }
	return m.createPrepared(namespace, domain, ipv6)
}
// Reserve the baseline cursor block without holding mappingAccess. Only Create
// serializes behind this writer; lookup, mapping pins and cancellation stay live.
// A publication that changes storage during I/O causes a reservation retry on
// the exact new handle, never writes through a mutable global backend pointer.
func (m *Manager) createPrepared(origin *memoryNamespace, domain string, ipv6 bool) (netip.Addr, error) {
	m.allocationAccess.Lock(); defer m.allocationAccess.Unlock()
	for {
		if err := m.ensureCounterCapacity(m.ctx, 1); err != nil { return netip.Addr{}, err }
		m.mappingAccess.Lock()
		if !m.counterCapacityLocked(1) { m.mappingAccess.Unlock(); continue }
		namespace := origin; if namespace == nil { namespace = m.active }
		if namespace.empty { m.mappingAccess.Unlock(); return netip.Addr{}, ErrNoActiveNamespace }
		if namespace.aborted || !namespace.published || namespace.compacted || namespace.store.storage == nil { m.mappingAccess.Unlock(); return netip.Addr{}, ErrMigrationStale }
		store, storage := namespace.store, namespace.store.storage
		namespace.operations++
		if m.storageOperations == nil { m.storageOperations = make(map[adapter.FakeIPStorage]uint64) }; m.storageOperations[storage]++
		legacy := m.authority == nil
		needsReservation := true
		if address, found := m.domains[domainKey{domain, ipv6}]; found && usableRange(store, address, ipv6) {
			needsReservation = false
			for _, record := range m.protection.byAddress[address] { if record.key.namespace != namespace.id && record.key.domain != domain { needsReservation = true; break } }
		}
		m.mappingAccess.Unlock()
		if legacy { _, cached := storage.FakeIPLoadDomain(domain, ipv6); needsReservation = !cached }
		var reservationErr error
		_, privateStorage := storage.(adapter.FakeIPRuntimeNamespace)
		if needsReservation || privateStorage {
			store.addressAccess.Lock()
			// Even a cached-domain first use must persist the current cursor in
			// the new private allocator. An old backend's reservation cannot be
			// spent after a pointer swap; ordinary later cache hits stay RAM-only.
			if needsReservation || store.reservationStorage != storage { reservationErr = store.reserveMetadata(storage) }
			store.addressAccess.Unlock()
		}
		m.mappingAccess.Lock()
		finishStorage := func() { namespace.operations--; m.storageOperations[storage]--; if m.storageOperations[storage] == 0 { delete(m.storageOperations, storage) }; m.persistenceChangedLocked() }
		if reservationErr != nil { finishStorage(); m.mappingAccess.Unlock(); return netip.Addr{}, reservationErr }
		if store.storage != storage || (origin == nil && m.active != namespace) { finishStorage(); m.mappingAccess.Unlock(); continue }
		address, err := m.createLocked(namespace, domain, ipv6)
		finishStorage(); m.mappingAccess.Unlock()
		return address, err
	}
}
func (m *Manager) createLocked(namespace *memoryNamespace, domain string, ipv6 bool) (netip.Addr, error) {
	if namespace.aborted || !namespace.published { return netip.Addr{}, ErrCandidateNotCommitted }
	if namespace.empty { return netip.Addr{}, ErrNoActiveNamespace }
	m.protection.prune(m.now()); m.collectNamespacesLocked()
	if namespace.compacted { return netip.Addr{}, ErrMigrationStale }
	if m.authority == nil {
		address, err := namespace.store.Create(domain, ipv6)
		if err == nil { m.protection.replaced(address, domain, m.now()); m.noteAllocationLocked(namespace, address, domain) }
		return address, err
	}
	if m.nextAnswerRevision == ^uint64(0) { return netip.Addr{}, ErrPersistenceIdentity }
	allowed := func(address netip.Addr) bool {
		for _, record := range m.protection.byAddress[address] {
			if record.key.namespace != namespace.id && record.key.domain != domain { return false }
		}
		return true
	}
	// Reuse a globally authoritative same-domain address if this configured
	// pool can allocate it. This shares identity across overlapping ranges.
	if address, found := m.domains[domainKey{domain, ipv6}]; found && usableRange(namespace.store, address, ipv6) && allowed(address) {
		if current, exists := namespace.store.storage.FakeIPLoad(address); !exists || current != domain { if err := namespace.store.storeMapping(address, domain); err != nil { return netip.Addr{}, err } }
		m.assignLocked(namespace, address, domain)
		return address, nil
	}
	address, err := namespace.store.createGuarded(domain, ipv6, func(address netip.Addr) bool {
		entry, found := m.authority[address]
		return found && entry.domain == domain && allowed(address)
	}, allowed)
	if err != nil { return netip.Addr{}, err }
	m.assignLocked(namespace, address, domain)
	return address, nil
}
func usableRange(store *Store, address netip.Addr, ipv6 bool) bool {
	if ipv6 { return usable(store.inet6Range, address) }
	return usable(store.inet4Range, address)
}
func (m *Manager) assignLocked(namespace *memoryNamespace, address netip.Addr, domain string) {
	var revision uint64
	newOwner := true
	if old, found := m.authority[address]; found {
		if old.domain == domain { revision = old.revision; newOwner = old.namespace != namespace }
		delete(old.namespace.owned, address)
		key := domainKey{old.domain, address.Is6()}
		if m.domains[key] == address { delete(m.domains, key) }
	}
	if revision == 0 { m.nextAnswerRevision++; revision = m.nextAnswerRevision; newOwner = true }
	m.authority[address] = authorityEntry{domain: domain, namespace: namespace, revision: revision}
	if newOwner && namespace.durable != nil { namespace.durable.handle.QueueAuthority(adapter.FakeIPRuntimeAnswer{Address: address, Domain: domain, Revision: revision, Obsolete: true}) }
	m.domains[domainKey{domain, address.Is6()}] = address
	if namespace.owned == nil { namespace.owned = make(map[netip.Addr]struct{}) }
	namespace.owned[address] = struct{}{}
	m.protection.replaced(address, domain, m.now())
	m.noteAllocationLocked(namespace, address, domain)
}

// The guard is used only after an in-memory migration. Before migration the
// exact baseline Store.Create path, cursor reservation and persistence remain.
func (s *Store) createGuarded(domain string, ipv6 bool, cached, allowed func(netip.Addr) bool) (netip.Addr, error) {
	s.addressAccess.Lock(); defer s.addressAccess.Unlock()
	if address, found := s.storage.FakeIPLoadDomain(domain, ipv6); found && cached(address) { return address, nil }
	prefix, last, current := s.inet4Range, s.inet4Last, s.inet4Current
	if ipv6 { prefix, last, current = s.inet6Range, s.inet6Last, s.inet6Current }
	if !prefix.IsValid() { return netip.Addr{}, errors.New("missing configured fake-IP address family") }
	first := nextAddress(prefix, last, current)
	address := first
	for !allowed(address) {
		address = nextAddress(prefix, last, address)
		if address == first { return netip.Addr{}, ErrAllocationConflict }
	}
	if err := s.storeMapping(address, domain); err != nil { return netip.Addr{}, err }
	if ipv6 { s.inet6Current = address } else { s.inet4Current = address }
	if s.reservedCount != 0 { s.reservedCount-- }
	return address, nil
}

func (m *Manager) retainedOwnerLocked(address netip.Addr, domain string) *memoryNamespace {
	for _, record := range m.protection.byAddress[address] {
		if record.key.domain == domain && record.current { return m.namespaces[record.key.namespace] }
	}
	return nil
}
func (m *Manager) collectNamespacesLocked() {
	// Remove expired individual retained identities incrementally; one long
	// active flow must not keep an old namespace's unrelated TTL map alive.
	for _, key := range m.protection.released {
		namespace := m.namespaces[key.namespace]
		if namespace == nil || !namespace.compacted { continue }
		entry, found := m.authority[key.address]
		if !found || entry.namespace != namespace { continue }
		owner := m.retainedOwnerLocked(key.address, entry.domain)
		if owner == namespace { continue }
		delete(namespace.owned, key.address)
		if owner != nil {
			m.authority[key.address] = authorityEntry{domain: entry.domain, namespace: owner, revision: entry.revision}
			owner.owned[key.address] = struct{}{}
		} else {
			delete(m.authority, key.address)
			domain := domainKey{entry.domain, key.address.Is6()}; if m.domains[domain] == key.address { delete(m.domains, domain) }
		}
	}
	m.protection.released = nil
	for id, namespace := range m.namespaces {
		if namespace == m.active || namespace.handles != 0 || namespace.operations != 0 { continue }
		if namespace.aborted { delete(m.namespaces, id); continue }
		if !namespace.retired { continue }
		if !namespace.compacted {
			// No old graph handle can allocate again. Drop its full allocator
			// cache and retain only authoritative identities with real guards.
			for address := range namespace.owned {
				entry := m.authority[address]
				owner := m.retainedOwnerLocked(address, entry.domain)
				if owner != nil {
					if owner != namespace { m.authority[address] = authorityEntry{domain: entry.domain, namespace: owner, revision: entry.revision}; owner.owned[address] = struct{}{}; delete(namespace.owned, address) }
					continue
				}
				delete(m.authority, address); delete(namespace.owned, address)
				key := domainKey{entry.domain, address.Is6()}; if m.domains[key] == address { delete(m.domains, key) }
			}
			namespace.store.storage = nil
			namespace.compacted = true
		}
		if m.protection.namespaceCounts[id] == 0 {
			for address := range namespace.owned {
				entry := m.authority[address]
				owner := m.retainedOwnerLocked(address, entry.domain)
				if owner != nil && owner != namespace { m.authority[address] = authorityEntry{domain: entry.domain, namespace: owner, revision: entry.revision}; owner.owned[address] = struct{}{}; continue }
				delete(m.authority, address)
				key := domainKey{entry.domain, address.Is6()}; if m.domains[key] == address { delete(m.domains, key) }
			}
			delete(m.namespaces, id)
		}
	}
}
