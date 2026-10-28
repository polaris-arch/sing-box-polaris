package fakeip

import (
	"container/heap"
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"

	mDNS "github.com/miekg/dns"
)

var (
	ErrAnswerIdentityChanged = errors.New("fake-IP answer no longer has its authoritative address/domain identity")
	ErrMappingReleased       = errors.New("fake-IP mapping reservation was released")
	ErrMappingNotFound       = errors.New("owned fake-IP address has no authoritative mapping")
)

type (
	mappingKey struct {
		namespace uint64
		address   netip.Addr
		domain    string
	}
	protectedMapping struct {
		key       mappingKey
		revision  uint64
		current   bool
		pending   uint64
		active    uint64
		expires   time.Time
		heapIndex int
	}
)
type expiryHeap []*protectedMapping

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].heapIndex = i; h[j].heapIndex = j }

func (h *expiryHeap) Push(value any) {
	record := value.(*protectedMapping)
	record.heapIndex = len(*h)
	*h = append(*h, record)
}

func (h *expiryHeap) Pop() any {
	old := *h
	record := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	record.heapIndex = -1
	return record
}

type protectionState struct {
	mappings        map[mappingKey]*protectedMapping
	current         map[netip.Addr]*protectedMapping
	expiries        expiryHeap
	byAddress       map[netip.Addr]map[mappingKey]*protectedMapping
	namespaceCounts map[uint64]int
	released        []mappingKey
}

func (s *protectionState) get(namespace uint64, address netip.Addr, domain string) *protectedMapping {
	if s.mappings == nil {
		s.mappings = make(map[mappingKey]*protectedMapping)
		s.current = make(map[netip.Addr]*protectedMapping)
		s.byAddress = make(map[netip.Addr]map[mappingKey]*protectedMapping)
		s.namespaceCounts = make(map[uint64]int)
	}
	key := mappingKey{namespace, address, domain}
	record := s.mappings[key]
	if record == nil {
		record = &protectedMapping{key: key, heapIndex: -1}
		s.mappings[key] = record
		if s.byAddress[address] == nil {
			s.byAddress[address] = make(map[mappingKey]*protectedMapping)
		}
		s.byAddress[address][key] = record
		s.namespaceCounts[namespace]++
	}
	if !record.current {
		record.revision = 0
	}
	record.current = true
	s.current[address] = record
	return record
}

func (s *protectionState) discardIfUnused(record *protectedMapping) {
	if record.pending != 0 || record.active != 0 || !record.expires.IsZero() {
		return
	}
	if s.mappings[record.key] != record {
		return
	}
	delete(s.mappings, record.key)
	s.released = append(s.released, record.key)
	delete(s.byAddress[record.key.address], record.key)
	if len(s.byAddress[record.key.address]) == 0 {
		delete(s.byAddress, record.key.address)
	}
	s.namespaceCounts[record.key.namespace]--
	if s.namespaceCounts[record.key.namespace] == 0 {
		delete(s.namespaceCounts, record.key.namespace)
	}
	if s.current[record.key.address] == record {
		delete(s.current, record.key.address)
	}
}

func (s *protectionState) clearExpiry(record *protectedMapping) {
	if record.heapIndex >= 0 {
		heap.Remove(&s.expiries, record.heapIndex)
	}
	record.expires = time.Time{}
}

func (s *protectionState) obsolete(record *protectedMapping) {
	// Ordinary same-store reuse remains baseline-compatible. It already ended
	// that old answer's authoritative identity. Do not resurrect its TTL later.
	// Pending egress and active consumers still retain their captured identity.
	record.current = false
	if s.current[record.key.address] == record {
		delete(s.current, record.key.address)
	}
	s.clearExpiry(record)
	s.discardIfUnused(record)
}

func (s *protectionState) prune(now time.Time) {
	for len(s.expiries) > 0 && !s.expiries[0].expires.After(now) {
		record := heap.Pop(&s.expiries).(*protectedMapping)
		record.expires = time.Time{}
		s.discardIfUnused(record)
	}
}

func (s *protectionState) replaced(address netip.Addr, domain string, now time.Time) {
	s.prune(now)
	for _, record := range s.byAddress[address] {
		if record.key.domain != domain {
			s.obsolete(record)
		}
	}
}

func (s *protectionState) extend(record *protectedMapping, expires time.Time) {
	if !record.current || !expires.After(record.expires) {
		return
	}
	record.expires = expires
	if record.heapIndex < 0 {
		heap.Push(&s.expiries, record)
	} else {
		heap.Fix(&s.expiries, record.heapIndex)
	}
}

// ProtectAnswer observes final rewritten TTLs. The manager's allocation mutex
// makes recognition and reservation atomic relative to this manager's Create.
// This is a data-serialization mutex, never the runtime admission lock.
func (m *Manager) ProtectAnswer(response *mDNS.Msg) (adapter.FakeIPAnswerLease, error) {
	return m.protectAnswerContext(m.ctx, nil, response)
}

func (m *Manager) ProtectAnswerContext(ctx context.Context, response *mDNS.Msg) (adapter.FakeIPAnswerLease, error) {
	return m.protectAnswerContext(ctx, nil, response)
}

func (m *Manager) protectAnswer(origin *memoryNamespace, response *mDNS.Msg) (adapter.FakeIPAnswerLease, error) {
	return m.protectAnswerContext(m.ctx, origin, response)
}

func (m *Manager) protectAnswerContext(ctx context.Context, origin *memoryNamespace, response *mDNS.Msg) (adapter.FakeIPAnswerLease, error) {
	done, ok := m.work.Reserve()
	if !ok {
		return nil, lifecycle.ErrStopped
	}
	if !m.started.Load() {
		done()
		return nil, ErrManagerNotStarted
	}
	var capacity uint64
	if response != nil {
		capacity = uint64(len(response.Answer))
	}
	capacity = max(capacity, 1)
	for {
		if err := m.waitAnswerAdmission(ctx); err != nil {
			done()
			return nil, err
		}
		if err := m.ensureCounterCapacity(ctx, capacity); err != nil {
			done()
			return nil, err
		}
		m.mappingAccess.Lock()
		if (m.answerHandoff == nil || m.answerHandoff.canceled.Load()) && m.counterCapacityLocked(capacity) {
			break
		}
		m.mappingAccess.Unlock()
	}
	if m.persistenceWindowLocked() && m.persistenceErr != nil {
		err := m.persistenceErr
		m.mappingAccess.Unlock()
		done()
		return nil, err
	}
	m.protection.prune(m.now())
	m.collectNamespacesLocked()
	if origin != nil && (!origin.published || m.namespaces[origin.id] != origin) {
		m.mappingAccess.Unlock()
		done()
		return nil, ErrMigrationStale
	}
	identities := make(map[mappingKey]uint32)
	if response != nil {
		for _, rr := range response.Answer {
			var address netip.Addr
			switch record := rr.(type) {
			case *mDNS.A:
				address, _ = netip.AddrFromSlice(record.A)
				address = address.Unmap()
			case *mDNS.AAAA:
				address, _ = netip.AddrFromSlice(record.AAAA)
			default:
				continue
			}
			if !m.containsLocked(address) {
				continue
			}
			domain, namespace, found := m.lookupLocked(address)
			if !found || !strings.EqualFold(domain, strings.TrimSuffix(rr.Header().Name, ".")) {
				m.mappingAccess.Unlock()
				done()
				return nil, ErrAnswerIdentityChanged
			}
			if origin != nil {
				if !origin.store.Contains(address) {
					m.mappingAccess.Unlock()
					done()
					return nil, ErrAnswerIdentityChanged
				}
				namespace = origin.id
			}
			key := mappingKey{namespace, address, domain}
			identities[key] = max(identities[key], rr.Header().Ttl)
		}
	}
	if len(identities) == 0 {
		m.mappingAccess.Unlock()
		done()
		return nil, nil
	}
	if m.nextAnswerToken == ^uint64(0) || m.nextAnswerRevision > ^uint64(0)-uint64(len(identities)) {
		m.mappingAccess.Unlock()
		done()
		return nil, ErrPersistenceIdentity
	}
	m.nextAnswerToken++
	answer := &answerLease{manager: m, token: m.nextAnswerToken, answers: make(map[*protectedMapping]uint32), identities: make(map[*protectedMapping]adapter.FakeIPRuntimeAnswer), journals: make(answerJournal), done: done}
	initialJournals := make(answerJournal)
	for key, ttl := range identities {
		record := m.protection.get(key.namespace, key.address, key.domain)
		if record.revision == 0 {
			if entry, exists := m.authority[key.address]; exists && entry.domain == key.domain {
				record.revision = entry.revision
			}
			if record.revision == 0 {
				m.nextAnswerRevision++
				record.revision = m.nextAnswerRevision
			}
		}
		record.pending++
		answer.answers[record] = ttl
		identity := adapter.FakeIPRuntimeAnswer{Token: answer.token, Address: key.address, Domain: key.domain, Revision: record.revision, Pending: 1, PendingTTL: ttl}
		answer.identities[record] = identity
		if namespace := m.namespaces[key.namespace]; namespace != nil && namespace.durable != nil && m.persistenceWindowLocked() {
			handle := namespace.durable.handle
			initialJournals[handle] = append(initialJournals[handle], identity)
		}
	}
	if m.pendingAnswers == nil {
		m.pendingAnswers = make(map[uint64]*answerLease)
	}
	m.pendingAnswers[answer.token] = answer
	// Registration owns even a queued observer closure. A concurrent migration
	// may replace namespace bindings before this worker starts; cleanup must
	// still see its exact old handles. Completing an unstarted token is a no-op.
	answer.journals = initialJournals
	m.mappingAccess.Unlock()
	if len(initialJournals) != 0 {
		job, cancel := m.persistenceWriter.submit(func() error {
			for handle, records := range initialJournals {
				if err := ctx.Err(); err != nil {
					return err
				}
				m.mappingAccess.Lock()
				if answer.completed {
					m.mappingAccess.Unlock()
					return context.Canceled
				}
				answer.journals[handle] = records
				m.mappingAccess.Unlock()
				if err := handle.Observe(ctx, records); err != nil {
					return err
				}
			}
			return nil
		})
		select {
		case err := <-job.result:
			if err != nil {
				answer.Abort()
				return nil, err
			}
		case <-ctx.Done():
			cancel()
			answer.Abort()
			return nil, ctx.Err()
		}
	}
	// Allocation remains independent of the handoff. If baseline reuse won
	// during durable observation, do not emit an identity we no longer own.
	m.mappingAccess.Lock()
	valid := true
	for record, identity := range answer.identities {
		if !record.current || record.revision != identity.Revision {
			valid = false
			break
		}
	}
	m.mappingAccess.Unlock()
	if !valid {
		answer.Abort()
		return nil, ErrAnswerIdentityChanged
	}
	return answer, nil
}

type answerLease struct {
	manager     *Manager
	token       uint64
	answers     map[*protectedMapping]uint32
	identities  map[*protectedMapping]adapter.FakeIPRuntimeAnswer
	journals    answerJournal // manager.mappingAccess; only certified/started writes
	completed   bool
	finished    bool
	completedAt time.Time
	delivered   bool
	done        func()
	once        sync.Once
}

func (a *answerLease) Delivered(at time.Time) { a.complete(at, true) }
func (a *answerLease) Abort()                 { a.complete(time.Time{}, false) }
func (a *answerLease) complete(at time.Time, delivered bool) {
	a.once.Do(func() {
		m := a.manager
		m.mappingAccess.Lock()
		now := m.now()
		if at.Before(now) {
			at = now
		}
		a.completed, a.completedAt, a.delivered = true, at, delivered
		for record, ttl := range a.answers {
			record.pending--
			if delivered && ttl != 0 {
				m.protection.extend(record, at.Add(time.Duration(ttl)*time.Second))
			}
			m.protection.discardIfUnused(record)
		}
		m.protection.prune(now)
		m.collectNamespacesLocked()
		journals := a.journals
		m.mappingAccess.Unlock()
		finish := func() {
			m.mappingAccess.Lock()
			a.finished = true
			delete(m.pendingAnswers, a.token)
			m.persistenceChangedLocked()
			m.mappingAccess.Unlock()
			a.done()
		}
		if len(journals) == 0 {
			finish()
			return
		}
		m.persistenceWriter.submit(func() error {
			defer finish()
			var failure error
			for handle, records := range journals {
				if err := lifecycle.CleanupResult("fake-IP answer completion", func() error { return handle.Complete(context.Background(), records, at, delivered) }); err != nil {
					failure = err
					m.retainFailedCompletion(persistentCompletion{handle, records, at, delivered}, err)
				}
			}
			return failure
		})
	})
}

func (m *Manager) AcquireMapping(address netip.Addr) (adapter.FakeIPMappingLease, bool, error) {
	done, ok := m.work.Reserve()
	if !ok {
		return nil, false, lifecycle.ErrStopped
	}
	if !m.started.Load() {
		done()
		return nil, false, ErrManagerNotStarted
	}
	m.mappingAccess.Lock()
	m.protection.prune(m.now())
	m.collectNamespacesLocked()
	if !m.containsLocked(address) {
		m.mappingAccess.Unlock()
		done()
		return nil, false, nil
	}
	domain, namespace, found := m.lookupLocked(address)
	if !found {
		m.mappingAccess.Unlock()
		done()
		return nil, false, ErrMappingNotFound
	}
	record := m.protection.get(namespace, address, domain)
	record.active++
	lineage := &mappingLineage{manager: m, record: record, references: 1, done: done}
	m.mappingAccess.Unlock()
	return &mappingLease{lineage: lineage}, true, nil
}

type mappingLineage struct {
	manager    *Manager
	record     *protectedMapping
	references uint64
	done       func()
}
type mappingLease struct {
	lineage  *mappingLineage
	released bool // guarded by manager.mappingAccess
}

func (l *mappingLease) Address() netip.Addr { return l.lineage.record.key.address }
func (l *mappingLease) Domain() string      { return l.lineage.record.key.domain }
func (l *mappingLease) Fork() (adapter.FakeIPMappingLease, error) {
	lineage := l.lineage
	lineage.manager.mappingAccess.Lock()
	defer lineage.manager.mappingAccess.Unlock()
	if l.released {
		return nil, ErrMappingReleased
	}
	lineage.references++
	return &mappingLease{lineage: lineage}, nil
}

func (l *mappingLease) Release() {
	lineage := l.lineage
	m := lineage.manager
	m.mappingAccess.Lock()
	if l.released {
		m.mappingAccess.Unlock()
		return
	}
	l.released = true
	lineage.references--
	last := lineage.references == 0
	if last {
		m.persistenceChangedLocked()
		lineage.record.active--
		m.protection.discardIfUnused(lineage.record)
		m.collectNamespacesLocked()
	}
	m.mappingAccess.Unlock()
	if last {
		lineage.done()
	}
}

var _ adapter.FakeIPProtection = (*Manager)(nil)
