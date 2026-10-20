package runtimegraph

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

var (
	ErrAdmissionSealed = errAdmissionSealed
	ErrAdmissionNotReady = errAdmissionNotReady
	ErrRevisionMismatch = errRevisionMismatch
	ErrInvalidGeneration = errInvalidGeneration
	ErrLeaseReleased = errLeaseReleased
	ErrResourceSealed = errResourceSealed
	ErrResourceNotMember = errors.New("resource is not in runtime closure")
)

// Graph is a prospective owner or an observation handle after publication.
// It contains no public mutable inventory. Discard is only for an unpublished
// candidate; publication transfers its sole prospective reference to Store.
type Graph struct { generation *generation }

// NewGraph forks reservations, leaving input handles with their caller. The
// view and all of its lookup shells must already be immutable. Every captured
// dependency is explicitly present in members; an ID cannot alias two owners.
func NewGraph(view adapter.RuntimeView, members []adapter.RuntimeResourceLease) (*Graph, error) {
	if view == nil { return nil, errInvalidGeneration }
	identity := view.Identity()
	if identity.Incarnation == "" || identity.Revision == 0 { return nil, errInvalidGeneration }
	g := newGeneration(identity.Revision)
	g.identity = identity
	g.view = view
	g.members = make(map[adapter.RuntimeResourceID]*resourceLease, len(members))
	fail := func(err error) (*Graph, error) { _ = g.discard(); return nil, err }
	for _, member := range members {
		lease, ok := member.(*resourceLease)
		if !ok || lease == nil || lease.owner == nil { return fail(ErrResourceNotMember) }
		id := lease.ID()
		if id.Incarnation != identity.Incarnation || id.Sequence == 0 { return fail(ErrResourceNotMember) }
		if _, exists := g.members[id]; exists { return fail(fmt.Errorf("duplicate runtime resource: %d", id.Sequence)) }
		retained, err := lease.forkGraphMembership()
		if err != nil { return fail(err) }
		g.members[id] = retained
	}
	for _, member := range g.members {
		for _, dependency := range member.owner.dependencies {
			bound := g.members[dependency.ID()]
			if bound == nil || bound.owner != dependency.owner { return fail(ErrResourceNotMember) }
		}
	}
	return &Graph{generation: g}, nil
}

func (g *Graph) Identity() adapter.RuntimeRevision { return g.generation.identity }
func (g *Graph) Discard() error { return g.generation.discard() }
// Drained proves graph exhaustion and membership release, not resource cleanup.
func (g *Graph) Drained() <-chan struct{} { return g.generation.drained }

func (g *generation) releaseMembers() {
	for _, member := range g.members { member.release() }
	close(g.drained)
}

func (l *generationLease) View() adapter.RuntimeView { return l.generation.view }
func (l *generationLease) Release() { l.release() }
func (l *generationLease) Fork() (adapter.RuntimeLease, error) {
	g := l.generation
	g.mu.Lock()
	defer g.mu.Unlock()
	// Retirement bars roots, not continuation from a still-live source.
	if l.released || g.refs == 0 { return nil, errLeaseReleased }
	if g.refs == ^uint64(0) { return nil, errInvalidGeneration }
	g.refs++
	return &generationLease{generation: g}, nil
}

func (l *generationLease) RetainResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	// Keep the graph alive while retaining a member, without nesting owner
	// mutexes. Source validity and the graph increment are one transition.
	continuation, err := l.Fork()
	if err != nil { return nil, err }
	defer continuation.Release()
	member := l.generation.members[id]
	if member == nil { return nil, ErrResourceNotMember }
	retained, err := member.fork()
	if err != nil { return nil, err }
	return retained, nil
}

// Store reuses admission's RLock/read/retain critical section. Only Box owns
// this facade; ingress gets the narrower adapter.RuntimeAdmission capability.
// NewStore starts unready. Only a ready revision-one graph may publish first.
type Store struct {
	admission *admission
	incarnation string
	graphs []*Graph // protected by admission.mu
	sealOnce sync.Once
	closed chan struct{}
	drained chan struct{}
}

func NewStore(incarnation string) (*Store, error) {
	if incarnation == "" { return nil, errInvalidGeneration }
	return &Store{admission: &admission{}, incarnation: incarnation, closed: make(chan struct{}), drained: make(chan struct{})}, nil
}

func (s *Store) Acquire() (adapter.RuntimeLease, error) {
	lease, err := s.admission.acquire()
	if err != nil { return nil, err }
	return lease, nil
}
func (s *Store) Closed() <-chan struct{} { return s.closed }
func (s *Store) Drained() <-chan struct{} { return s.drained }

// PreparedPublication is an already-fenced, infallible in-memory activation.
// It must perform no I/O, allocation, blocking acquisition or user callback.
// All fallible preparation and lock acquisition precede PublishPrepared.
type PreparedPublication interface { Publish() }

func (s *Store) Publish(expected adapter.RuntimeRevision, candidate *Graph) (*Graph, error) {
	return s.PublishPrepared(expected, candidate, nil)
}

// PublishPrepared activates candidate-only state at the same admission boundary
// as the graph pointer. Rejection never invokes prepared. The participant is
// owned by the caller, which aborts its held fence on every rejected publication.
func (s *Store) PublishPrepared(expected adapter.RuntimeRevision, candidate *Graph, prepared PreparedPublication) (*Graph, error) {
	if candidate == nil || candidate.generation == nil { return nil, errInvalidGeneration }
	next := candidate.generation
	identity := candidate.Identity()
	a := s.admission
	a.mu.Lock()
	if a.sealed { a.mu.Unlock(); return nil, errAdmissionSealed }
	old := a.current
	currentRevision := uint64(0)
	if old != nil { currentRevision = old.revision }
	if expected.Incarnation != s.incarnation || expected.Revision != currentRevision {
		a.mu.Unlock(); return nil, errRevisionMismatch
	}
	if currentRevision == ^uint64(0) || identity.Incarnation != s.incarnation || identity.Revision != currentRevision + 1 {
		a.mu.Unlock(); return nil, errInvalidGeneration
	}
	next.mu.Lock()
	claimed := next.claimLocked()
	next.mu.Unlock()
	if !claimed { a.mu.Unlock(); return nil, errInvalidGeneration }
	if old != nil {
		old.mu.Lock()
		old.retired = true
		old.mu.Unlock()
	}
	// Prune only already-drained observations; no new lifetime counter.
	kept := s.graphs[:0]
	for _, graph := range s.graphs {
		select { case <-graph.Drained(): default: kept = append(kept, graph) }
	}
	clear(s.graphs[len(kept):])
	s.graphs = append(kept, candidate)
	a.current = next
	if prepared != nil { prepared.Publish() }
	a.mu.Unlock()
	if old != nil { old.drop(); return &Graph{generation: old}, nil }
	return nil, nil
}

// Seal is nonjoining and executes no component callback. Drained closes only
// after every published graph releases its memberships; Box separately joins
// resource owners before its stable providers may close.
func (s *Store) Seal() {
	s.sealOnce.Do(func() {
		s.admission.seal()
		close(s.closed)
		s.admission.mu.RLock()
		graphs := append([]*Graph(nil), s.graphs...)
		s.admission.mu.RUnlock()
		go func() {
			for _, graph := range graphs { <-graph.Drained() }
			s.admission.mu.Lock(); s.graphs = nil; s.admission.mu.Unlock()
			close(s.drained)
		}()
	})
}

// ResourceOwner is a narrow Box allocation authority over the existing owner.
// There is one owner per actual resource or inseparable cleanup cohort.
type ResourceOwner struct { owner *resourceOwner }

func NewResourceOwner(parent context.Context, id adapter.RuntimeResourceID, dependencies []adapter.RuntimeResourceLease, closeFn func() error) (*ResourceOwner, error) {
	if parent == nil || id.Incarnation == "" || id.Sequence == 0 { return nil, ErrResourceNotMember }
	retained := make([]*resourceLease, 0, len(dependencies))
	seen := make(map[adapter.RuntimeResourceID]bool, len(dependencies))
	fail := func(err error) (*ResourceOwner, error) {
		for _, lease := range retained { lease.release() }
		return nil, err
	}
	for _, dependency := range dependencies {
		lease, ok := dependency.(*resourceLease)
		if !ok || lease == nil || lease.owner == nil { return fail(ErrResourceNotMember) }
		dependencyID := lease.ID()
		if dependencyID.Incarnation != id.Incarnation || dependencyID.Sequence == 0 || dependencyID == id || seen[dependencyID] {
			return fail(ErrResourceNotMember)
		}
		copy, err := lease.fork()
		if err != nil { return fail(err) }
		seen[dependencyID] = true
		retained = append(retained, copy)
	}
	owner := newResourceOwner(parent, closeFn)
	owner.id = id
	owner.dependencies = retained
	return &ResourceOwner{owner: owner}, nil
}

func (o *ResourceOwner) ID() adapter.RuntimeResourceID { return o.owner.id }
func (o *ResourceOwner) Context() context.Context { return o.owner.context() }
func (o *ResourceOwner) Acquire() (adapter.RuntimeResourceLease, error) {
	lease, err := o.owner.acquire()
	if err != nil { return nil, err }
	return lease, nil
}
func (o *ResourceOwner) Seal() { o.owner.requestClose() }
func (o *ResourceOwner) Retiring() <-chan struct{} { return o.owner.retiring }
func (o *ResourceOwner) Closed() <-chan struct{} { return o.owner.closed }
func (o *ResourceOwner) WaitClosed(ctx context.Context) error { return o.owner.waitClosed(ctx) }

// RetainExisting is solely for Box's current-plus-retained callback census.
// The catalog stores identity, never a permanent reservation; zero-to-one and
// closing-owner resurrection are prohibited. It is not root ingress admission.
func (o *ResourceOwner) RetainExisting() (adapter.RuntimeResourceLease, error) {
	r := o.owner
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refs == 0 || r.state >= resourceClosing { return nil, errResourceSealed }
	if r.refs == ^uint64(0) { return nil, errors.New("resource reference overflow") }
	r.refs++
	return &resourceLease{owner: r}, nil
}

func (l *resourceLease) ID() adapter.RuntimeResourceID { return l.owner.id }
func (l *resourceLease) Retiring() <-chan struct{} { return l.owner.retiring }
func (l *resourceLease) Release() { l.release() }
func (l *resourceLease) Fork() (adapter.RuntimeResourceLease, error) {
	lease, err := l.fork()
	if err != nil { return nil, err }
	return lease, nil
}
func (l *resourceLease) fork() (*resourceLease, error) {
	r := l.owner
	r.mu.Lock()
	defer r.mu.Unlock()
	if l.released || r.refs == 0 || r.state >= resourceClosing { return nil, errLeaseReleased }
	if r.refs == ^uint64(0) { return nil, errors.New("resource reference overflow") }
	r.refs++
	return &resourceLease{owner: r}, nil
}

// A new candidate is new graph membership, not an old operation's continuation.
// Box must reserve candidate membership before deciding an owner is old-only.
func (l *resourceLease) forkGraphMembership() (*resourceLease, error) {
	r := l.owner
	r.mu.Lock()
	defer r.mu.Unlock()
	if l.released || r.refs == 0 { return nil, errLeaseReleased }
	if r.state != resourceOpen { return nil, errResourceSealed }
	if r.refs == ^uint64(0) { return nil, errors.New("resource reference overflow") }
	r.refs++
	return &resourceLease{owner: r}, nil
}
