package fakeip

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

var (
	ErrRecoveryAnchorRequired = errors.New("fake-IP durable migration needs a discoverable custody anchor")
	ErrPersistencePending     = errors.New("previous fake-IP backend transition awaits exact configuration durability acknowledgement")
	ErrPersistencePreparing   = errors.New("another fake-IP durable preparation or cleanup is still retained")
	ErrRecoveryConflict       = errors.New("recovered fake-IP namespaces have conflicting live address identities")
	ErrPersistenceIdentity    = errors.New("fake-IP persistence transaction or effective configuration identity is missing")
)

type PersistentMigrationOptions struct {
	// Backend nil means memory allocation. Anchor still journals migration
	// recognition until actual old answers/flows drain and config is durable.
	Backend                  adapter.FakeIPRuntimeBackend
	Anchor                   adapter.FakeIPRuntimeBackend
	Resolver                 adapter.FakeIPRuntimeResolver
	TransactionID            string
	EffectiveConfigurationID string
}

type namespacePersistence struct {
	handle     adapter.FakeIPRuntimeNamespace
	backend    adapter.FakeIPRuntimeBackend
	allocation bool
}
type answerJournal map[adapter.FakeIPRuntimeNamespace][]adapter.FakeIPRuntimeAnswer

type persistentNamespaceImage struct {
	namespace *memoryNamespace
	storage   adapter.FakeIPStorage
	metadata  adapter.FakeIPMetadata
	snapshot  adapter.FakeIPStorageSnapshot
	backend   adapter.FakeIPRuntimeBackend
	binding   *namespacePersistence
	seed      map[*protectedMapping]uint64
}
type (
	persistentCompletion struct {
		handle    adapter.FakeIPRuntimeNamespace
		answers   []adapter.FakeIPRuntimeAnswer
		at        time.Time
		delivered bool
	}
	persistentResult struct {
		commit *RangeCommit
		impact MigrationImpact
		err    error
	}
)

type persistentPreparation struct {
	candidate              *RangeMigration
	options                PersistentMigrationOptions
	gate                   chan struct{}
	gateOnce               sync.Once
	terminal               chan struct{}
	terminalOnce           sync.Once
	started                atomic.Bool
	canceled               atomic.Bool
	commit                 atomic.Pointer[RangeCommit]
	result                 chan persistentResult
	finished               chan struct{}
	counterFloor           adapter.FakeIPRuntimeCounters
	counterCeiling         adapter.FakeIPRuntimeCounters
	anchor                 adapter.FakeIPRuntimeBackend
	ownerDone              func()
	images                 []*persistentNamespaceImage
	created                []adapter.FakeIPRuntimeNamespace
	backends               map[adapter.FakeIPRuntimeBackendDescriptor]adapter.FakeIPRuntimeBackend
	releases               map[adapter.FakeIPRuntimeBackendDescriptor]func() error
	link                   adapter.FakeIPRuntimeLink
	deltas                 map[netip.Addr]authorityEntry // manager.mappingAccess
	leases                 []*answerLease
	transfers              map[*answerLease]answerJournal
	post                   []persistentCompletion
	superseded             []adapter.FakeIPRuntimeNamespace
	publicationTransitions []*persistentPreparation
	acknowledged           bool  // manager.mappingAccess
	cleanupErr             error // after finished, or manager.mappingAccess
	completionErr          error // writer-owned; read only after finished
}

func (p *persistentPreparation) openGate()       { p.gateOnce.Do(func() { close(p.gate) }) }
func (p *persistentPreparation) signalTerminal() { p.terminalOnce.Do(func() { close(p.terminal) }) }
func (p *persistentPreparation) cancel() {
	if commit := p.commit.Load(); commit != nil {
		// Once handed to the coordinator, only its explicit Publish/Abort owns
		// the final fence. A late context callback cannot race graph publication.
		if !commit.state.CompareAndSwap(0, 2) {
			return
		}
		p.canceled.Store(true)
		commit.abortClaimedState()
		p.candidate.ActivatePersistence()
		return
	}
	p.canceled.Store(true)
	p.openGate()
}

func (m *Manager) PreparePersistentRanges(ctx context.Context, inet4Range, inet6Range netip.Prefix, options PersistentMigrationOptions) (*RangeMigration, error) {
	return m.preparePersistent(ctx, inet4Range, inet6Range, options, false)
}

// PreparePersistentRemoval gives the selected disabled configuration its own
// durable transition identity. Old transports and recognition keep their actual
// namespaces; the published empty allocator cannot create or emit new answers.
func (m *Manager) PreparePersistentRemoval(ctx context.Context, options PersistentMigrationOptions) (*RangeMigration, error) {
	return m.preparePersistent(ctx, netip.Prefix{}, netip.Prefix{}, options, true)
}

func (m *Manager) preparePersistent(ctx context.Context, inet4Range, inet6Range netip.Prefix, options PersistentMigrationOptions, removal bool) (*RangeMigration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.TransactionID == "" || options.EffectiveConfigurationID == "" {
		return nil, ErrPersistenceIdentity
	}
	if options.Anchor == nil || options.Resolver == nil {
		return nil, ErrRecoveryAnchorRequired
	}
	if !removal {
		if err := validRanges(inet4Range, inet6Range); err != nil {
			return nil, err
		}
	}
	done, ok := m.work.Reserve()
	if !ok {
		return nil, lifecycle.ErrStopped
	}
	m.mappingAccess.Lock()
	defer m.mappingAccess.Unlock()
	if !m.started.Load() {
		done()
		return nil, ErrManagerNotStarted
	}
	if m.preparing != nil {
		done()
		return nil, ErrPersistencePreparing
	}
	for _, transition := range m.transitions {
		if !transition.acknowledged {
			done()
			return nil, ErrPersistencePending
		}
	}
	if m.nextNamespace == ^uint64(0) {
		done()
		return nil, ErrMigrationStale
	}
	m.nextNamespace++
	store := NewStore(m.store.ctx, m.store.logger, inet4Range.Masked(), inet6Range.Masked())
	store.storage = NewMemoryStorage()
	if store.inet4Range.IsValid() {
		store.inet4Current = store.inet4Range.Addr().Next()
	}
	if store.inet6Range.IsValid() {
		store.inet6Current = store.inet6Range.Addr().Next()
	}
	namespace := &memoryNamespace{id: m.nextNamespace, empty: removal, store: store, owned: make(map[netip.Addr]struct{})}
	m.namespaces[namespace.id] = namespace
	candidate := &RangeMigration{manager: m, namespace: namespace, base: m.active, permit: NewAnswerPermit()}
	preparation := &persistentPreparation{candidate: candidate, options: options, gate: make(chan struct{}), terminal: make(chan struct{}), result: make(chan persistentResult, 1), finished: make(chan struct{}), ownerDone: done, backends: make(map[adapter.FakeIPRuntimeBackendDescriptor]adapter.FakeIPRuntimeBackend), releases: make(map[adapter.FakeIPRuntimeBackendDescriptor]func() error), deltas: make(map[netip.Addr]authorityEntry)}
	candidate.persistent = preparation
	candidate.done = preparation.signalTerminal
	m.preparing = preparation
	return candidate, nil
}

// PrepareDurableCommit gates only final fake-IP answer admission, never Create,
// recognition or active flows. One private worker performs I/O outside all
// manager/publication locks. Cancellation reopens admission immediately; it does
// not release that worker, its namespaces or physical backend reservations.
func (c *RangeMigration) PrepareDurableCommit(ctx context.Context) (*RangeCommit, MigrationImpact, error) {
	p := c.persistent
	if p == nil {
		return c.PrepareCommit()
	}
	if !p.started.CompareAndSwap(false, true) {
		return nil, MigrationImpact{}, ErrMigrationStale
	}
	m := c.manager
	m.mappingAccess.Lock()
	if c.state.Load() != 0 || m.active != c.base || m.work.Sealed() {
		m.mappingAccess.Unlock()
		p.cancel()
		c.state.Store(3)
		p.cleanupAborted()
		close(p.finished)
		return nil, MigrationImpact{}, ErrMigrationStale
	}
	if m.nextAnswerRevision > ^uint64(0)-uint64(len(m.protection.mappings)) {
		m.mappingAccess.Unlock()
		p.cancel()
		c.state.Store(3)
		p.cleanupAborted()
		close(p.finished)
		return nil, MigrationImpact{}, ErrPersistenceIdentity
	}
	m.answerHandoff = p
	m.protection.prune(m.now())
	for _, namespace := range m.namespaces {
		if !namespace.published && namespace != c.namespace {
			continue
		}
		if namespace.empty {
			continue
		}
		image := &persistentNamespaceImage{namespace: namespace, storage: namespace.store.storage, metadata: adapter.FakeIPMetadata{Inet4Range: namespace.store.inet4Range, Inet6Range: namespace.store.inet6Range, Inet4Current: namespace.store.inet4Current, Inet6Current: namespace.store.inet6Current}, seed: make(map[*protectedMapping]uint64)}
		image.snapshot = adapter.FakeIPStorageSnapshot{Mappings: make(map[netip.Addr]string)}
		if namespace == c.namespace {
			image.backend = p.options.Backend
		} else if namespace.durable != nil {
			image.backend = namespace.durable.backend
		} else if backend, ok := image.storage.(adapter.FakeIPRuntimeBackend); ok {
			image.backend = backend
		}
		if image.backend == nil {
			image.backend = p.options.Anchor
		}
		for _, record := range m.protection.mappings {
			if record.key.namespace != namespace.id || !record.current {
				continue
			}
			if record.revision == 0 {
				continue
			} // active-only flows do not survive process restart
			image.snapshot.Answers = append(image.snapshot.Answers, adapter.FakeIPRuntimeAnswer{Address: record.key.address, Domain: record.key.domain, Revision: record.revision, Pending: record.pending, ExpiresAt: record.expires})
			image.seed[record] = record.revision
		}
		if image.storage == nil {
			for address := range namespace.owned {
				if entry, found := m.authority[address]; found {
					image.snapshot.Mappings[address] = entry.domain
				}
			}
		}
		p.images = append(p.images, image)
	}
	for _, lease := range m.pendingAnswers {
		p.leases = append(p.leases, lease)
		for _, image := range p.images {
			for record, answer := range lease.identities {
				if record.key.namespace == image.namespace.id && record.current {
					answer.Revision = record.revision
					image.snapshot.PendingAnswers = append(image.snapshot.PendingAnswers, answer)
				}
			}
		}
	}
	m.mappingAccess.Unlock()
	go p.run(ctx)
	select {
	case result := <-p.result:
		if result.err != nil {
			return nil, result.impact, result.err
		}
		if !result.commit.state.CompareAndSwap(0, 3) {
			return nil, result.impact, context.Canceled
		}
		if p.canceled.Load() {
			result.commit.Abort()
			c.ActivatePersistence()
			return nil, result.impact, context.Canceled
		}
		return result.commit, result.impact, nil
	case <-ctx.Done():
		p.cancel()
		return nil, MigrationImpact{}, ctx.Err()
	}
}

func (p *persistentPreparation) retainBackend(ctx context.Context, backend adapter.FakeIPRuntimeBackend) (adapter.FakeIPRuntimeBackendDescriptor, error) {
	descriptor, err := backend.RuntimeDescriptor(ctx)
	if err != nil {
		return descriptor, err
	}
	if _, exists := p.backends[descriptor]; exists {
		return descriptor, nil
	}
	retained, release, err := p.options.Resolver.ResolveFakeIPRuntime(ctx, descriptor)
	if err != nil {
		return descriptor, err
	}
	actual, err := retained.RuntimeDescriptor(ctx)
	if err != nil || actual != descriptor {
		_ = release()
		if err != nil {
			return descriptor, err
		}
		return descriptor, ErrPersistenceIdentity
	}
	p.backends[descriptor] = retained
	p.releases[descriptor] = release
	return descriptor, nil
}

func storageSnapshot(ctx context.Context, storage adapter.FakeIPStorage) (adapter.FakeIPStorageSnapshot, error) {
	if storage == nil {
		return adapter.FakeIPStorageSnapshot{Mappings: make(map[netip.Addr]string)}, nil
	}
	if namespace, ok := storage.(adapter.FakeIPRuntimeNamespace); ok {
		return namespace.SnapshotAllocation(), nil
	}
	if backend, ok := storage.(adapter.FakeIPRuntimeBackend); ok {
		return backend.SnapshotFakeIP(ctx)
	}
	if memory, ok := storage.(*MemoryStorage); ok {
		snapshot := adapter.FakeIPStorageSnapshot{Mappings: make(map[netip.Addr]string)}
		memory.addressAccess.RLock()
		maps.Copy(snapshot.Mappings, memory.addressCache)
		memory.addressAccess.RUnlock()
		return snapshot, nil
	}
	return adapter.FakeIPStorageSnapshot{}, ErrPersistentMigrationRequired
}

func (p *persistentPreparation) prepareStorage(ctx context.Context) error {
	anchor, err := p.retainBackend(ctx, p.options.Anchor)
	if err != nil {
		return err
	}
	p.anchor = p.backends[anchor]
	m := p.candidate.manager
	m.mappingAccess.Lock()
	minimum := adapter.FakeIPRuntimeCounters{Revision: m.nextAnswerRevision, Token: m.nextAnswerToken}
	boundAnchor := m.counterRoot
	m.mappingAccess.Unlock()
	if boundAnchor != nil && boundAnchor != p.anchor {
		return ErrPersistenceIdentity
	}
	p.counterFloor, p.counterCeiling, err = p.anchor.ReserveFakeIPRuntimeCounters(ctx, minimum, reservedAddressCount)
	if err != nil {
		return err
	}
	generation, err := p.anchor.AllocateFakeIPGeneration(ctx)
	if err != nil {
		return err
	}
	p.link = adapter.FakeIPRuntimeLink{ID: p.options.TransactionID, EffectiveConfigurationID: p.options.EffectiveConfigurationID}
	// A zero-range anchor namespace makes path discovery independent of which
	// cache is selected by the persisted configuration, including cache disabled.
	anchorDescriptor := adapter.FakeIPRuntimeNamespaceDescriptor{Version: 1, AnchorDatabaseID: anchor.DatabaseID, Backend: anchor, ID: p.options.TransactionID + "/anchor", EffectiveConfigurationID: p.options.EffectiveConfigurationID, LogicalID: p.options.TransactionID + "/anchor", Generation: generation}
	anchorHandle, err := p.backends[anchor].PrepareFakeIPNamespace(ctx, anchorDescriptor, adapter.FakeIPStorageSnapshot{Metadata: new(adapter.FakeIPMetadata), Mappings: make(map[netip.Addr]string)})
	if err != nil {
		return err
	}
	p.created = append(p.created, anchorHandle)
	p.link.Namespaces = append(p.link.Namespaces, anchorDescriptor)
	for _, image := range p.images {
		if p.canceled.Load() {
			return context.Canceled
		}
		backend, err := p.retainBackend(ctx, image.backend)
		if err != nil {
			return err
		}
		raw, err := storageSnapshot(ctx, image.storage)
		if err != nil {
			return err
		}
		if image.storage != nil {
			image.snapshot.Mappings = raw.Mappings
		}
		if image.namespace == p.candidate.namespace && p.candidate.base.empty && p.options.Backend != nil {
			selected, err := p.selectStartupAllocator(ctx, backend, image.metadata)
			if err != nil {
				return err
			}
			if selected.Metadata != nil {
				image.snapshot.Mappings = selected.Mappings
				image.metadata = *selected.Metadata
			}
		}
		metadata := image.metadata
		image.snapshot.Metadata = &metadata
		// Compute the aggregate from exact tokens, rather than extending every
		// interrupted answer on every restart.
		type revisionAddress struct {
			address  netip.Addr
			revision uint64
		}
		aggregates := make(map[revisionAddress]adapter.FakeIPRuntimeAnswer)
		for _, token := range image.snapshot.PendingAnswers {
			key := revisionAddress{token.Address, token.Revision}
			aggregate := aggregates[key]
			aggregate.Pending++
			aggregate.PendingTTL = max(aggregate.PendingTTL, token.PendingTTL)
			aggregates[key] = aggregate
		}
		for index := range image.snapshot.Answers {
			answer := &image.snapshot.Answers[index]
			aggregate := aggregates[revisionAddress{answer.Address, answer.Revision}]
			answer.Pending, answer.PendingTTL = aggregate.Pending, aggregate.PendingTTL
		}
		logicalID := p.options.TransactionID + "/logical/" + strconv.FormatUint(image.namespace.id, 10)
		if image.namespace.durable != nil {
			logicalID = image.namespace.durable.handle.Descriptor().LogicalID
		}
		descriptor := adapter.FakeIPRuntimeNamespaceDescriptor{Version: 1, AnchorDatabaseID: anchor.DatabaseID, Backend: backend, ID: p.options.TransactionID + "/" + strconv.FormatUint(image.namespace.id, 10), EffectiveConfigurationID: p.options.EffectiveConfigurationID, LogicalID: logicalID, Allocator: image.namespace == p.candidate.namespace && p.options.Backend != nil, Generation: generation}
		handle, err := p.backends[backend].PrepareFakeIPNamespace(ctx, descriptor, image.snapshot)
		if err != nil {
			return err
		}
		allocation := false
		if image.namespace == p.candidate.namespace {
			allocation = p.options.Backend != nil
		} else {
			_, memory := image.storage.(*MemoryStorage)
			allocation = image.storage != nil && !memory
		}
		image.binding = &namespacePersistence{handle: handle, backend: p.backends[backend], allocation: allocation}
		p.created = append(p.created, handle)
		p.link.Namespaces = append(p.link.Namespaces, descriptor)
	}
	// All participants are durable before publication. Partial writes are
	// inert: no new graph answer permit has opened; cancellation cleans them
	// only after this actual writer returns, never by racing a late commit.
	for _, backend := range p.backends {
		if err := backend.SaveFakeIPRuntimeLink(ctx, p.link); err != nil {
			return err
		}
	}
	p.link.DiscoveryReady = true
	if err := p.backends[anchor].SaveFakeIPRuntimeLink(ctx, p.link); err != nil {
		return err
	}
	return nil
}

func (p *persistentPreparation) run(ctx context.Context) {
	p.candidate.manager.persistenceMaintenance.Lock()
	defer p.candidate.manager.persistenceMaintenance.Unlock()
	defer close(p.finished)
	err := p.prepareStorage(ctx)
	var commit *RangeCommit
	var impact MigrationImpact
	if err == nil {
		commit, impact, err = p.prepareFence(ctx)
	}
	if err != nil {
		p.cancel()
		p.candidate.state.Store(3)
		p.result <- persistentResult{err: err}
		p.cleanupAborted()
		return
	}
	p.commit.Store(commit)
	if p.canceled.Load() || ctx.Err() != nil {
		commit.Abort()
		p.candidate.ActivatePersistence()
	}
	p.result <- persistentResult{commit: commit, impact: impact}
	select {
	case <-p.terminal:
	case <-ctx.Done():
		p.cancel()
		<-p.terminal
	}
	if p.candidate.state.Load() != 2 {
		p.cleanupAborted()
		return
	}
	for _, completion := range p.post {
		if err := completion.handle.Complete(context.Background(), completion.answers, completion.at, completion.delivered); err != nil {
			p.candidate.manager.retainFailedCompletion(completion, err)
			p.completionErr = fmt.Errorf("fake-IP post-publication completion retained: %v", err)
		}
	}
	p.candidate.manager.mappingAccess.Lock()
	if p.candidate.manager.preparing == p {
		p.candidate.manager.preparing = nil
	}
	p.images, p.transfers, p.post, p.deltas, p.publicationTransitions = nil, nil, nil, nil, nil
	p.candidate.manager.persistenceChangedLocked()
	p.candidate.manager.mappingAccess.Unlock()
	p.ownerDone()
}

// At most the finite set of identities captured before the answer gate can be
// invalidated by baseline Create/reuse. New allocations continue and are folded
// into the in-memory authority delta; they cannot create new delivered answers
// until the gate opens. Thus catch-up does not require traffic quiescence.
func (p *persistentPreparation) prepareFence(ctx context.Context) (*RangeCommit, MigrationImpact, error) {
	m := p.candidate.manager
	invalidated := make(map[*protectedMapping]bool)
	for {
		if p.canceled.Load() {
			return nil, MigrationImpact{}, context.Canceled
		}
		if err := ctx.Err(); err != nil {
			return nil, MigrationImpact{}, err
		}
		m.mappingAccess.Lock()
		if m.active != p.candidate.base || p.candidate.state.Load() != 0 {
			m.mappingAccess.Unlock()
			return nil, MigrationImpact{}, ErrMigrationStale
		}
		toInvalidate := make(map[adapter.FakeIPRuntimeNamespace][]adapter.FakeIPRuntimeAnswer)
		for _, image := range p.images {
			for record, revision := range image.seed {
				if !invalidated[record] && (!record.current || record.revision != revision) {
					toInvalidate[image.binding.handle] = append(toInvalidate[image.binding.handle], adapter.FakeIPRuntimeAnswer{Address: record.key.address, Domain: record.key.domain, Revision: revision})
					invalidated[record] = true
				}
			}
		}
		if len(toInvalidate) != 0 {
			m.mappingAccess.Unlock()
			for handle, identities := range toInvalidate {
				if err := handle.Invalidate(ctx, identities); err != nil {
					return nil, MigrationImpact{}, err
				}
			}
			continue
		}
		m.protection.prune(m.now())
		impact := m.migrationImpactLocked(p.candidate.namespace)
		if capacityBlocked(impact.IPv4) || capacityBlocked(impact.IPv6) {
			m.mappingAccess.Unlock()
			return nil, impact, &MigrationConflictError{Impact: impact}
		}
		if !p.candidate.state.CompareAndSwap(0, 1) || !p.candidate.permit.state.CompareAndSwap(0, 3) {
			m.mappingAccess.Unlock()
			return nil, impact, ErrMigrationStale
		}
		// Same-range backend replacement preserves the live cursor. Cold startup
		// resumes a matching explicitly selected allocator image, never its config.
		for _, image := range p.images {
			if image.namespace == p.candidate.namespace {
				if p.candidate.base.store.inet4Range == image.namespace.store.inet4Range && p.candidate.base.store.inet6Range == image.namespace.store.inet6Range {
					image.namespace.store.inet4Current, image.namespace.store.inet6Current = p.candidate.base.store.inet4Current, p.candidate.base.store.inet6Current
				} else if p.candidate.base.empty {
					image.namespace.store.inet4Current, image.namespace.store.inet6Current = image.metadata.Inet4Current, image.metadata.Inet6Current
				}
			}
		}
		commit := &RangeCommit{candidate: p.candidate, authority: make(map[netip.Addr]authorityEntry), domains: make(map[domainKey]netip.Addr), owned: make(map[*memoryNamespace]map[netip.Addr]struct{})}
		if m.authority != nil {
			maps.Copy(commit.authority, m.authority)
		} else {
			for _, image := range p.images {
				if image.namespace.published {
					for address, domain := range image.snapshot.Mappings {
						commit.authority[address] = authorityEntry{domain: domain, namespace: image.namespace}
					}
				}
			}
			maps.Copy(commit.authority, p.deltas)
		}
		if p.candidate.base.empty {
			for _, image := range p.images {
				if image.namespace == p.candidate.namespace {
					for address, domain := range image.snapshot.Mappings {
						if _, protected := commit.authority[address]; !protected {
							commit.authority[address] = authorityEntry{domain: domain, namespace: image.namespace}
						}
					}
				}
			}
		}
		for address, entry := range commit.authority {
			if entry.revision == 0 {
				if record := m.protection.current[address]; record != nil && record.current && record.key.domain == entry.domain {
					entry.revision = record.revision
					commit.authority[address] = entry
				}
			}
			commit.domains[domainKey{entry.domain, address.Is6()}] = address
			if commit.owned[entry.namespace] == nil {
				commit.owned[entry.namespace] = make(map[netip.Addr]struct{})
			}
			commit.owned[entry.namespace][address] = struct{}{}
		}
		p.transfers = make(map[*answerLease]answerJournal)
		for _, lease := range p.leases {
			journals := make(answerJournal)
			maps.Copy(journals, lease.journals)
			for _, image := range p.images {
				var records []adapter.FakeIPRuntimeAnswer
				for _, token := range image.snapshot.PendingAnswers {
					if token.Token == lease.token {
						records = append(records, token)
					}
				}
				if len(records) == 0 {
					continue
				}
				if lease.completed {
					p.post = append(p.post, persistentCompletion{image.binding.handle, records, lease.completedAt, lease.delivered})
				} else {
					journals[image.binding.handle] = records
				}
			}
			if !lease.completed {
				p.transfers[lease] = journals
			}
		}
		p.publicationTransitions = append(append([]*persistentPreparation(nil), m.transitions...), p)
		for _, image := range p.images {
			if image.namespace.durable != nil {
				p.superseded = append(p.superseded, image.namespace.durable.handle)
			}
		}
		return commit, impact, nil // short RAM fence held for publication
	}
}

func (p *persistentPreparation) publishLocked() {
	m := p.candidate.manager
	for _, image := range p.images {
		image.namespace.durable = image.binding
		if image.binding.allocation {
			image.namespace.store.storage = image.binding.handle
		}
	}
	for lease, journals := range p.transfers {
		lease.journals = journals
	}
	m.counterRoot = p.anchor
	m.persistenceResolver = p.options.Resolver
	m.nextAnswerRevision = max(m.nextAnswerRevision, p.counterFloor.Revision)
	m.nextAnswerToken = max(m.nextAnswerToken, p.counterFloor.Token)
	m.counterCeiling.Revision = max(m.counterCeiling.Revision, p.counterCeiling.Revision)
	m.counterCeiling.Token = max(m.counterCeiling.Token, p.counterCeiling.Token)
	m.transitions = p.publicationTransitions
}

func (p *persistentPreparation) recordError(err error) {
	if err == nil {
		return
	}
	m := p.candidate.manager
	m.mappingAccess.Lock()
	m.persistenceErr = fmt.Errorf("fake-IP persistence incomplete: %v", err)
	m.mappingAccess.Unlock()
}

func (p *persistentPreparation) cleanupAborted() {
	var failures []error
	// Make discovery inert before removing any private bucket. The actual
	// candidate writer has terminated and no candidate permit was published.
	if p.anchor != nil {
		if err := p.anchor.RemoveFakeIPRuntimeLink(context.Background(), p.options.TransactionID); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) == 0 {
		for _, backend := range p.backends {
			if err := backend.RemoveFakeIPRuntimeLink(context.Background(), p.options.TransactionID); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if len(failures) == 0 {
		for _, handle := range p.created {
			if err := handle.Abort(context.Background()); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if len(failures) == 0 {
		for descriptor, release := range p.releases {
			if err := release(); err != nil {
				failures = append(failures, err)
			} else {
				delete(p.releases, descriptor)
			}
		}
	}
	m := p.candidate.manager
	m.mappingAccess.Lock()
	p.cleanupErr = nil
	if len(failures) != 0 {
		p.cleanupErr = fmt.Errorf("fake-IP candidate cleanup incomplete: %v", errors.Join(failures...))
	}
	p.candidate.namespace.aborted = true
	if m.answerHandoff == p {
		m.answerHandoff = nil
	}
	if len(failures) == 0 && m.preparing == p {
		m.preparing = nil
	}
	m.mappingAccess.Unlock()
	p.openGate()
	if len(failures) != 0 {
		p.recordError(p.cleanupErr)
	}
	p.ownerDone()
}

func (m *Manager) waitAnswerAdmission(ctx context.Context) error {
	for {
		m.mappingAccess.Lock()
		gate := m.answerHandoff
		if gate == nil || gate.canceled.Load() {
			m.mappingAccess.Unlock()
			return ctx.Err()
		}
		m.mappingAccess.Unlock()
		select {
		case <-gate.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *Manager) persistenceWindowLocked() bool {
	if m.preparing != nil {
		return true
	}
	for _, transition := range m.transitions {
		if !transition.acknowledged {
			return true
		}
	}
	for _, namespace := range m.namespaces {
		if namespace != m.active && namespace.published && (namespace.handles != 0 || m.protection.namespaceCounts[namespace.id] != 0) {
			return true
		}
	}
	return false
}

func (m *Manager) noteAllocationLocked(namespace *memoryNamespace, address netip.Addr, domain string) {
	if m.preparing != nil && !m.preparing.canceled.Load() {
		entry := authorityEntry{domain: domain, namespace: namespace}
		if current, found := m.authority[address]; found {
			entry = current
		}
		m.preparing.deltas[address] = entry
	}
}

// AcknowledgePersistence is called only after the coordinator has persisted the
// exact canonical effective configuration. RAM publication is insufficient.
func (m *Manager) AcknowledgePersistence(ctx context.Context, effectiveID string) error {
	m.persistenceMaintenance.Lock()
	defer m.persistenceMaintenance.Unlock()
	done, ok := m.work.Reserve()
	if !ok {
		return lifecycle.ErrStopped
	}
	defer done()
	m.mappingAccess.Lock()
	var transition *persistentPreparation
	for _, candidate := range m.transitions {
		if candidate.options.EffectiveConfigurationID == effectiveID {
			transition = candidate
			break
		}
	}
	m.mappingAccess.Unlock()
	if transition == nil {
		m.mappingAccess.Lock()
		defer m.mappingAccess.Unlock()
		if m.recovered == nil || m.recovered.selection != effectiveID {
			return ErrPersistenceIdentity
		}
		// This hook follows successful canonical persistence, not merely the
		// initial selection. No link's different target is reinterpreted.
		m.recovered.selectionAcknowledged = true
		m.persistenceChangedLocked()
		return nil
	}
	link := transition.link
	link.Acknowledged = true
	for _, backend := range transition.backends {
		if err := backend.SaveFakeIPRuntimeLink(ctx, link); err != nil {
			return err
		}
	}
	m.mappingAccess.Lock()
	transition.acknowledged = true
	m.persistenceChangedLocked()
	m.mappingAccess.Unlock()
	return nil
}

// WaitPersistence reports actual post-publication completion. A canceled wait
// never releases the still-running writer or its backend dependency closure.
func (c *RangeMigration) WaitPersistence(ctx context.Context) error {
	if c.persistent == nil {
		return nil
	}
	select {
	case <-c.persistent.finished:
		c.manager.mappingAccess.Lock()
		err := errors.Join(c.persistent.cleanupErr, c.persistent.completionErr)
		c.manager.mappingAccess.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// AcknowledgePersistence binds the caller's canonical persistence receipt to
// this exact migration. Memory-only range changes have no durable journal to
// acknowledge. A different revision may never acknowledge this transition.
func (c *RangeMigration) AcknowledgePersistence(ctx context.Context, effectiveID string) error {
	if c.persistent == nil {
		return nil
	}
	if effectiveID != c.persistent.options.EffectiveConfigurationID {
		return ErrPersistenceIdentity
	}
	if err := c.WaitPersistence(ctx); err != nil {
		return err
	}
	return c.manager.AcknowledgePersistence(ctx, effectiveID)
}

// Selection is an allocator image lookup under the caller's explicit config.
// Unissued preparations never outrank an issued matching namespace. Recovery's
// separate valid-answer union overrides any stale ordinary batched mapping.
func (p *persistentPreparation) selectStartupAllocator(ctx context.Context, backend adapter.FakeIPRuntimeBackendDescriptor, metadata adapter.FakeIPMetadata) (adapter.FakeIPStorageSnapshot, error) {
	var selected adapter.FakeIPStorageSnapshot
	var generation uint64
	m := p.candidate.manager
	if m.recovered != nil {
		for _, handle := range m.recovered.handles {
			descriptor := handle.Descriptor()
			if !descriptor.Allocator || descriptor.Backend != backend || descriptor.EffectiveConfigurationID != p.options.EffectiveConfigurationID {
				continue
			}
			snapshot, err := handle.Snapshot(ctx)
			if err != nil {
				return selected, err
			}
			if !snapshot.Issued || snapshot.Metadata == nil || snapshot.Metadata.Inet4Range != metadata.Inet4Range || snapshot.Metadata.Inet6Range != metadata.Inet6Range {
				continue
			}
			if descriptor.Generation == 0 || descriptor.Generation == generation {
				return selected, ErrPersistenceIdentity
			}
			if descriptor.Generation > generation {
				generation, selected = descriptor.Generation, snapshot
			}
		}
	}
	if selected.Metadata != nil {
		return selected, nil
	}
	legacy, err := p.backends[backend].SnapshotFakeIP(ctx)
	if err != nil {
		return selected, err
	}
	if legacy.Metadata != nil && legacy.Metadata.Inet4Range == metadata.Inet4Range && legacy.Metadata.Inet6Range == metadata.Inet6Range {
		return legacy, nil
	}
	return selected, nil
}
