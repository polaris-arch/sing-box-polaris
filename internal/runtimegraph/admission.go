// Package runtimegraph owns graph and resource lifetime counters. Concrete
// runtime views and publication policy belong to Box, not this package.
package runtimegraph

import (
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

var (
	errAdmissionSealed   = errors.New("generation admission sealed")
	errRevisionMismatch  = errors.New("generation revision mismatch")
	errInvalidGeneration = errors.New("invalid or already owned generation")
	errAdmissionNotReady = errors.New("generation admission not ready")
	errLeaseReleased     = errors.New("runtime lease released")
)

// generation holds one fixed typed view and its declared resource closure.
// revision is immutable. All other fields are protected by mu. The zero signal
// proves graph reference exhaustion, not completion of resource cleanup.
// A constructor-created generation has one prospective owner reference.
// Its owner may be claimed exactly once, including across admission instances.
type generation struct {
	mu       sync.Mutex
	revision uint64
	refs     uint64
	claimed  bool
	retired  bool
	zero     chan struct{}
	identity adapter.RuntimeRevision
	view     adapter.RuntimeView
	members  map[adapter.RuntimeResourceID]*resourceLease
	drained  chan struct{}
}

func newGeneration(revision uint64) *generation {
	return &generation{revision: revision, refs: 1, zero: make(chan struct{}), drained: make(chan struct{})}
}

// claimLocked transfers the prospective owner; it does not add a reference.
func (g *generation) claimLocked() bool {
	if g.zero == nil || g.drained == nil || g.claimed || g.retired || g.refs != 1 {
		return false
	}
	g.claimed = true
	return true
}

// discard abandons a caller-owned candidate, including after failed publish.
// It cannot release an admission's owner reference.
func (g *generation) discard() error {
	g.mu.Lock()
	if g.claimed || g.retired || g.zero == nil || g.refs != 1 {
		g.mu.Unlock()
		return errInvalidGeneration
	}
	g.retired = true
	zero := g.dropLocked()
	g.mu.Unlock()
	if zero {
		g.releaseMembers()
	}
	return nil
}

func (g *generation) dropLocked() bool {
	if g.refs == 0 {
		panic("runtimegraph: generation reference underflow")
	}
	g.refs--
	if g.refs == 0 {
		close(g.zero)
		return true
	}
	return false
}

func (g *generation) drop() {
	g.mu.Lock()
	zero := g.dropLocked()
	g.mu.Unlock()
	if zero {
		g.releaseMembers()
	}
}

// Lock order is admission.mu then generation.mu, never the reverse. No user
// callback, I/O, cleanup, or join runs under either lock.
type admission struct {
	mu      sync.RWMutex
	current *generation
	sealed  bool
}

// newAdmission consumes initial's prospective owner only on success.
func newAdmission(initial *generation) (*admission, error) {
	if initial == nil {
		return nil, errInvalidGeneration
	}
	initial.mu.Lock()
	ok := initial.claimLocked()
	initial.mu.Unlock()
	if !ok {
		return nil, errInvalidGeneration
	}
	return &admission{current: initial}, nil
}

type generationLease struct {
	generation *generation
	released   bool // protected by generation.mu, together with refs
}

func (a *admission) acquire() (*generationLease, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.acquireLocked()
}

// acquireLocked requires admission.mu read or write ownership.
func (a *admission) acquireLocked() (*generationLease, error) {
	if a.sealed {
		return nil, errAdmissionSealed
	}
	g := a.current
	if g == nil {
		return nil, errAdmissionNotReady
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	// Retain remains inside the admission read guard: publish/seal cannot
	// detach the owner between reading current and acquiring this reference.
	if g.retired || g.refs == 0 || g.refs == ^uint64(0) {
		return nil, errInvalidGeneration
	}
	g.refs++
	return &generationLease{generation: g}, nil
}

func (l *generationLease) release() {
	g := l.generation
	g.mu.Lock()
	if l.released {
		g.mu.Unlock()
		return
	}
	l.released = true
	zero := g.dropLocked()
	g.mu.Unlock()
	if zero {
		g.releaseMembers()
	}
}

// publish transfers next's prospective owner only on success. A failed call
// does not itself transfer ownership or mutate next. A previously caller-owned
// candidate remains caller-owned only if no concurrent claim or discard wins.
// Returned old is observation only, never an ownership transfer or permission
// to close resources early.
func (a *admission) publish(expectedRevision uint64, next *generation) (*generation, error) {
	a.mu.Lock()
	if a.sealed {
		a.mu.Unlock()
		return nil, errAdmissionSealed
	}
	old := a.current
	if old.revision != expectedRevision {
		a.mu.Unlock()
		return nil, errRevisionMismatch
	}
	if next == nil || next == old || next.revision <= old.revision {
		a.mu.Unlock()
		return nil, errInvalidGeneration
	}
	next.mu.Lock()
	ok := next.claimLocked()
	next.mu.Unlock()
	if !ok {
		a.mu.Unlock()
		return nil, errInvalidGeneration
	}
	old.mu.Lock()
	old.retired = true
	old.mu.Unlock()
	a.current = next
	a.mu.Unlock()
	old.drop()
	return old, nil
}

// seal is idempotent. Retirement is recorded while admission is exclusive;
// owner release and ref-zero publication occur after the guard is released.
func (a *admission) seal() *generation {
	a.mu.Lock()
	if a.sealed {
		a.mu.Unlock()
		return nil
	}
	a.sealed = true
	old := a.current
	a.current = nil
	if old != nil {
		old.mu.Lock()
		old.retired = true
		old.mu.Unlock()
	}
	a.mu.Unlock()
	if old != nil {
		old.drop()
	}
	return old
}
