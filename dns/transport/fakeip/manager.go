package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing/common/logger"
)

var (
	ErrMigrationRequired   = errors.New("fake-IP range or backing-store replacement requires issued-answer migration")
	ErrRecognitionReadOnly = errors.New("fake-IP recognition view is read-only")
	ErrManagerNotStarted   = errors.New("Box fake-IP allocator has not started")
	ErrManagerRequired     = errors.New("runtime fake-IP transport requires the Box-owned allocator")
)

// Manager owns the exact existing allocator for one Box lifetime. Its identity
// survives same-range transport replacement and removal. It intentionally does
// not change the existing cursor capacity, reuse policy or cache-file format.
// In-memory range migration uses a shared authority plus final-answer and active
// mapping guards. Persistent namespace migration is a separate capability;
// unchanged-range persistence remains the exact existing Store implementation.
type Manager struct {
	ctx                    context.Context
	store                  *Store
	work                   lifecycle.Work
	startOnce              sync.Once
	startErr               error
	started                atomic.Bool
	closeOnce              sync.Once
	closeErr               error
	recognition            recognitionStore
	mappingAccess          sync.Mutex
	allocationAccess       sync.Mutex
	storageOperations      map[adapter.FakeIPStorage]uint64
	protection             protectionState
	now                    func() time.Time
	active                 *memoryNamespace
	namespaces             map[uint64]*memoryNamespace
	nextNamespace          uint64
	authority              map[netip.Addr]authorityEntry
	domains                map[domainKey]netip.Addr
	nextAnswerRevision     uint64
	nextAnswerToken        uint64
	pendingAnswers         map[uint64]*answerLease
	answerHandoff          *persistentPreparation
	preparing              *persistentPreparation
	transitions            []*persistentPreparation
	persistenceErr         error
	persistenceWriter      persistenceExecutor
	recovered              *recoveredPersistence
	persistenceMaintenance sync.Mutex
	failedCompletions      map[*persistentCompletion]struct{}
	persistenceChanged     chan struct{}
	counterAccess          sync.Mutex
	persistenceResolver    adapter.FakeIPRuntimeResolver
	counterRoot            adapter.FakeIPRuntimeBackend
	counterCeiling         adapter.FakeIPRuntimeCounters
}

func NewManager(ctx context.Context, logger logger.Logger, inet4Range, inet6Range netip.Prefix) (*Manager, error) {
	if !inet4Range.IsValid() && !inet6Range.IsValid() {
		return nil, errors.New("fake-IP manager requires at least one address range")
	}
	if inet4Range.IsValid() && (!inet4Range.Addr().Is4() || inet4Range.Bits() > 30) {
		return nil, errors.New("fake-IP IPv4 range has no allocatable address")
	}
	if inet6Range.IsValid() && (!inet6Range.Addr().Is6() || inet6Range.Addr().Is4In6() || inet6Range.Bits() > 126) {
		return nil, errors.New("fake-IP IPv6 range has no allocatable address")
	}
	manager := &Manager{ctx: ctx, store: NewStore(ctx, logger, inet4Range.Masked(), inet6Range.Masked()), now: time.Now}
	manager.active = &memoryNamespace{id: 1, store: manager.store, published: true}
	manager.namespaces = map[uint64]*memoryNamespace{1: manager.active}
	manager.nextNamespace = 1
	manager.recognition.manager = manager
	return manager, nil
}

// NewEmptyManager establishes stable Box recognition before fake-IP is enabled.
// Start does not open/reset fake-IP storage. First activation is prepared and
// published through the same RangeMigration boundary as later replacements.
func NewEmptyManager(ctx context.Context, logger logger.Logger) *Manager {
	manager := &Manager{ctx: ctx, store: NewStore(ctx, logger, netip.Prefix{}, netip.Prefix{}), now: time.Now}
	manager.active = &memoryNamespace{id: 1, store: manager.store, published: true, empty: true}
	manager.namespaces = map[uint64]*memoryNamespace{1: manager.active}
	manager.nextNamespace = 1
	manager.recognition.manager = manager
	return manager
}

type managerContextKey struct{}

func ContextWithManager(ctx context.Context, manager *Manager) context.Context {
	return adapter.ContextWithFakeIPProtection(context.WithValue(ctx, managerContextKey{}, manager), manager)
}

func ManagerFromContext(ctx context.Context) (*Manager, bool) {
	manager, ok := ctx.Value(managerContextKey{}).(*Manager)
	return manager, ok && manager != nil
}

// Borrow is preparation-only: no Start, cache reset, cursor movement or issued
// answer is produced. Abort closes just this handle. Box retains the Manager.
func (m *Manager) Borrow(inet4Range, inet6Range netip.Prefix) (adapter.FakeIPStore, error) {
	done, ok := m.work.Reserve()
	if !ok {
		return nil, lifecycle.ErrStopped
	}
	defer done()
	m.mappingAccess.Lock()
	defer m.mappingAccess.Unlock()
	if m.active.empty {
		return nil, ErrNoActiveNamespace
	}
	if inet4Range.Masked() != m.active.store.inet4Range || inet6Range.Masked() != m.active.store.inet6Range {
		return nil, ErrMigrationRequired
	}
	m.active.handles++
	return &borrowedStore{manager: m, namespace: m.active}, nil
}

// BorrowCandidate has no allocation side effects and requires publication before
// Create. Start is only the existing once-only Box allocator initialization.
func (m *Manager) BorrowCandidate(inet4Range, inet6Range netip.Prefix, permit *AnswerPermit) (adapter.FakeIPStore, error) {
	if permit == nil {
		return nil, ErrAnswerPermitRequired
	}
	store, err := m.Borrow(inet4Range, inet6Range)
	if err != nil {
		return nil, err
	}
	store.(*borrowedStore).permit = permit
	return store, nil
}

func (m *Manager) Start() error {
	done, ok := m.work.Reserve()
	if !ok {
		return lifecycle.ErrStopped
	}
	defer done()
	m.startOnce.Do(func() {
		if !m.active.empty {
			m.startErr = m.store.Start()
		}
		m.started.Store(m.startErr == nil)
	})
	return m.startErr
}

func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.work.Seal()
		m.work.Wait()
		m.persistenceWriter.close()
		if m.started.Load() {
			m.closeErr = lifecycle.Uncertain("Box fake-IP allocator", errors.Join(m.store.Close(), m.closePersistence()))
		}
	})
	return m.closeErr
}

func (m *Manager) RecognitionStore() adapter.FakeIPStore { return &m.recognition }

func (m *Manager) create(domain string, isIPv6 bool) (netip.Addr, error) {
	done, ok := m.work.Reserve()
	if !ok {
		return netip.Addr{}, lifecycle.ErrStopped
	}
	defer done()
	if !m.started.Load() {
		return netip.Addr{}, ErrManagerNotStarted
	}
	return m.createPrepared(nil, domain, isIPv6)
}

func (m *Manager) lookup(address netip.Addr) (string, bool) {
	done, ok := m.work.Reserve()
	if !ok {
		return "", false
	}
	defer done()
	if !m.started.Load() {
		return "", false
	}
	m.mappingAccess.Lock()
	defer m.mappingAccess.Unlock()
	m.protection.prune(m.now())
	m.collectNamespacesLocked()
	domain, _, found := m.lookupLocked(address)
	return domain, found
}

type borrowedStore struct {
	manager   *Manager
	permit    *AnswerPermit
	namespace *memoryNamespace
	work      lifecycle.Work
	closeOnce sync.Once
}

func (s *borrowedStore) Start() error {
	done, ok := s.work.Reserve()
	if !ok {
		return lifecycle.ErrStopped
	}
	defer done()
	return s.manager.Start()
}

func (s *borrowedStore) Close() error {
	s.closeOnce.Do(func() {
		s.work.Seal()
		s.work.Wait()
		m := s.manager
		m.mappingAccess.Lock()
		s.namespace.handles--
		m.persistenceChangedLocked()
		m.protection.prune(m.now())
		m.collectNamespacesLocked()
		m.mappingAccess.Unlock()
	})
	return nil
}

func (s *borrowedStore) Contains(address netip.Addr) bool { return s.namespace.store.Contains(address) }

func (s *borrowedStore) Create(domain string, isIPv6 bool) (netip.Addr, error) {
	done, ok := s.work.Reserve()
	if !ok {
		return netip.Addr{}, lifecycle.ErrStopped
	}
	defer done()
	if s.permit != nil && !s.permit.admitted() {
		return netip.Addr{}, ErrCandidateNotCommitted
	}
	return s.manager.createFor(s.namespace, domain, isIPv6)
}

func (s *borrowedStore) Lookup(address netip.Addr) (string, bool) { return s.manager.lookup(address) }
func (s *borrowedStore) Reset() error                             { return ErrRecognitionReadOnly }

type recognitionStore struct{ manager *Manager }

func (s *recognitionStore) Start() error                     { return nil }
func (s *recognitionStore) Close() error                     { return nil }
func (s *recognitionStore) Contains(address netip.Addr) bool { return s.manager.contains(address) }
func (s *recognitionStore) Lookup(address netip.Addr) (string, bool) {
	return s.manager.lookup(address)
}

func (s *recognitionStore) Create(string, bool) (netip.Addr, error) {
	return netip.Addr{}, ErrRecognitionReadOnly
}
func (s *recognitionStore) Reset() error { return ErrRecognitionReadOnly }

var (
	_ adapter.FakeIPStore = (*borrowedStore)(nil)
	_ adapter.FakeIPStore = (*recognitionStore)(nil)
)

// RuntimeRangeIdentity observes the retained allocator even while no active
// graph exposes a fake-IP DNS server. Removal must not erase old references.
func (m *Manager) RuntimeRangeIdentity() (netip.Prefix, netip.Prefix, bool) {
	m.mappingAccess.Lock()
	defer m.mappingAccess.Unlock()
	if m.active == nil || m.active.empty {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	return m.active.store.inet4Range, m.active.store.inet6Range, true
}
