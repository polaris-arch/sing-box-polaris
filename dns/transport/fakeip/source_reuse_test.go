package fakeip

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

// The existing backend models the actual namespace/journal protocol in memory.
// These tests do not claim physical database or device durability.
type sourceReuseInventory struct {
	selected       *memoryNamespace
	store          *Store
	durableHandle  adapter.FakeIPRuntimeNamespace
	nextNamespace  uint64
	namespaceCount int
	transitions    int
	preparing      *persistentPreparation
	generation     uint64
	namespaces     map[string]*runtimeFixtureNamespace
	descriptors    map[string]adapter.FakeIPRuntimeNamespaceDescriptor
	links          map[string]adapter.FakeIPRuntimeLink
	reclaims       int
	linkRemovals   int
	counterCalls   int
	resolverCalls  int
	resolverRefs   int
}

func sourceReuseInspect(m *Manager, backend *runtimeFixtureBackend, resolver *runtimeFixtureResolver) sourceReuseInventory {
	m.mappingAccess.Lock()
	state := sourceReuseInventory{
		selected: m.active, store: m.store, nextNamespace: m.nextNamespace,
		namespaceCount: len(m.namespaces), transitions: len(m.transitions), preparing: m.preparing,
	}
	if m.active.durable != nil {
		state.durableHandle = m.active.durable.handle
	}
	m.mappingAccess.Unlock()
	backend.access.Lock()
	state.generation = backend.generation
	state.reclaims, state.linkRemovals, state.counterCalls = backend.reclaims, backend.linkRemovals, backend.counterCalls
	state.namespaces = make(map[string]*runtimeFixtureNamespace, len(backend.namespaces))
	state.descriptors = make(map[string]adapter.FakeIPRuntimeNamespaceDescriptor, len(backend.namespaces))
	for id, object := range backend.namespaces {
		state.namespaces[id] = object
		state.descriptors[id] = object.Descriptor()
	}
	state.links = make(map[string]adapter.FakeIPRuntimeLink, len(backend.links))
	for id, link := range backend.links {
		link.Namespaces = append([]adapter.FakeIPRuntimeNamespaceDescriptor(nil), link.Namespaces...)
		state.links[id] = link
	}
	backend.access.Unlock()
	resolver.access.Lock()
	state.resolverCalls, state.resolverRefs = len(resolver.requested), resolver.references
	resolver.access.Unlock()
	return state
}

func sourceReuseRequireInventory(t *testing.T, before sourceReuseInventory, m *Manager, backend *runtimeFixtureBackend, resolver *runtimeFixtureResolver) {
	t.Helper()
	if after := sourceReuseInspect(m, backend, resolver); !reflect.DeepEqual(before, after) {
		t.Fatalf("unchanged/rejected candidate changed actual namespace/backend/link inventory:\nbefore=%+v\nafter=%+v", before, after)
	}
}

func sourceReusePublishDurable(t *testing.T, candidate *RangeMigration) {
	t.Helper()
	t.Cleanup(candidate.Abort)
	fence, _, err := candidate.PrepareDurableCommit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Abort()
	fence.Publish()
	candidate.ActivatePersistence()
	if err := candidate.WaitPersistence(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Establish selection through the actual persistent prepare/fence/worker/ACK,
// rather than assigning Manager.active or supplying a fabricated ready flag.
func sourceReuseSelected(t *testing.T) (*Manager, *runtimeFixtureBackend, *runtimeFixtureResolver, netip.Prefix, netip.Prefix) {
	t.Helper()
	m := fixtureEmptyManager(t)
	m.now = func() time.Time { return time.Unix(100, 0) }
	backend := fixtureBackend("source-selected")
	resolver := fixtureResolver(backend)
	v4, v6 := netip.MustParsePrefix("198.18.0.0/29"), netip.MustParsePrefix("fc00::/125")
	options := fixtureOptions(backend, resolver, "source-base")
	options.Backend = backend
	candidate, err := m.PreparePersistentRanges(context.Background(), v4, v6, options)
	if err != nil {
		t.Fatal(err)
	}
	sourceReusePublishDurable(t, candidate)
	if err := candidate.AcknowledgePersistence(context.Background(), options.EffectiveConfigurationID); err != nil {
		t.Fatal(err)
	}
	// Collect the retired empty initial selection before capturing inventories.
	if !m.contains(v4.Addr().Next().Next()) {
		t.Fatal("actual selected persistent namespace does not recognize its range")
	}
	state := sourceReuseInspect(m, backend, resolver)
	if state.selected.empty || state.durableHandle == nil || state.namespaceCount != 1 ||
		state.nextNamespace != state.selected.id || state.preparing != nil || state.transitions != 1 {
		t.Fatalf("fixture did not establish one settled selected Manager namespace: %+v", state)
	}
	if state.store != state.selected.store || state.store.storage != state.durableHandle {
		t.Fatal("selected allocator is not using the actual persistent namespace handle")
	}
	p := candidate.persistent
	if p == nil || candidate.namespace != state.selected || !p.acknowledged ||
		p.options.TransactionID != options.TransactionID || p.options.EffectiveConfigurationID != options.EffectiveConfigurationID {
		t.Fatal("selected namespace lost its actual original acknowledged participant")
	}
	backendID, err := backend.RuntimeDescriptor(context.Background())
	if err != nil || backendID.DatabaseID == "" || state.generation == 0 {
		t.Fatal("original backend/generation identity is unavailable", err)
	}
	// Backend discovery has two distinct roles: a zero-range anchor and the
	// one selected allocator. Neither a bucket count nor a shared pointer alone
	// proves their exact original transaction, backend and generation closure.
	anchorID := options.TransactionID + "/anchor"
	allocatorID := fmt.Sprintf("%s/%d", options.TransactionID, state.selected.id)
	expected := map[string]adapter.FakeIPRuntimeNamespaceDescriptor{
		anchorID: {
			Version: 1, AnchorDatabaseID: backendID.DatabaseID, Backend: backendID,
			ID: anchorID, LogicalID: anchorID, EffectiveConfigurationID: options.EffectiveConfigurationID,
			Generation: state.generation,
		},
		allocatorID: {
			Version: 1, AnchorDatabaseID: backendID.DatabaseID, Backend: backendID,
			ID: allocatorID, LogicalID: fmt.Sprintf("%s/logical/%d", options.TransactionID, state.selected.id),
			EffectiveConfigurationID: options.EffectiveConfigurationID, Allocator: true, Generation: state.generation,
		},
	}
	if len(state.descriptors) != len(expected) || len(p.created) != len(expected) ||
		!reflect.DeepEqual(state.descriptors, expected) {
		t.Fatalf("backend does not contain the exact anchor/allocator owner closure: %+v", state.descriptors)
	}
	if state.namespaces[allocatorID] != state.durableHandle || state.durableHandle.Descriptor() != expected[allocatorID] {
		t.Fatal("actual selected handle is not the original linked allocator")
	}
	anchor := state.namespaces[anchorID]
	if anchor == nil || anchor == state.namespaces[allocatorID] {
		t.Fatal("discovery anchor aliases or replaces the selected allocator")
	}
	anchorImage, err := anchor.Snapshot(context.Background())
	if err != nil || anchorImage.Metadata == nil || anchorImage.Metadata.Inet4Range.IsValid() ||
		anchorImage.Metadata.Inet6Range.IsValid() || len(anchorImage.Mappings) != 0 ||
		len(anchorImage.Answers) != 0 || len(anchorImage.PendingAnswers) != 0 || anchorImage.Issued {
		t.Fatal("discovery anchor unexpectedly owns allocator ranges or issued answers", err)
	}
	allocatorImage := state.durableHandle.SnapshotAllocation()
	if allocatorImage.Metadata == nil || allocatorImage.Metadata.Inet4Range != v4 || allocatorImage.Metadata.Inet6Range != v6 {
		t.Fatal("selected allocator metadata is not the actually prepared range pair")
	}
	created := make(map[string]bool, len(p.created))
	for _, handle := range p.created {
		descriptor := handle.Descriptor()
		want, known := expected[descriptor.ID]
		if !known || descriptor != want || created[descriptor.ID] || state.namespaces[descriptor.ID] != handle {
			t.Fatal("original participant contains a duplicate, foreign or substituted namespace")
		}
		created[descriptor.ID] = true
	}
	link, found := state.links[options.TransactionID]
	if !found || len(state.links) != 1 || link.ID != options.TransactionID ||
		link.EffectiveConfigurationID != options.EffectiveConfigurationID || !link.DiscoveryReady || !link.Acknowledged ||
		len(link.Namespaces) != len(expected) {
		t.Fatal("original owner link is missing, unready, unacknowledged or has an unexpected participant set")
	}
	linked := make(map[string]bool, len(link.Namespaces))
	for _, descriptor := range link.Namespaces {
		want, known := expected[descriptor.ID]
		if !known || descriptor != want || linked[descriptor.ID] {
			t.Fatal("original owner link duplicated or borrowed another namespace/generation")
		}
		linked[descriptor.ID] = true
	}
	return m, backend, resolver, v4, v6
}

func sourceReuseRequireMapping(t *testing.T, m *Manager, address netip.Addr, domain string) {
	t.Helper()
	if actual, found := m.lookup(address); !found || actual != domain {
		t.Fatalf("old issued answer lost authoritative recognition: %s %q %v", address, actual, found)
	}
	flow, found, err := m.AcquireMapping(address)
	if err != nil || !found {
		t.Fatalf("old issued answer cannot create a real mapping lease: %v", err)
	}
	defer flow.Release()
	if flow.Address() != address || flow.Domain() != domain {
		t.Fatal("real flow lease changed the original address/domain identity")
	}
}

func sourceReuseBorrow(t *testing.T, candidate *RangeMigration, v4, v6 netip.Prefix) adapter.FakeIPStore {
	t.Helper()
	t.Cleanup(candidate.Abort)
	store, err := candidate.Borrow(v4, v6)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.Create("before-candidate-commit.example", false); !errors.Is(err, ErrCandidateNotCommitted) {
		t.Fatal("unpublished candidate issued an answer", err)
	}
	return store
}

func TestSourceUnchangedPersistentSelectionReusesNamespaceTwice(t *testing.T) {
	m, backend, resolver, v4, v6 := sourceReuseSelected(t)
	address, err := m.create("retained-source.example", false)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := m.ProtectAnswer(fakeAnswer(address, "retained-source.example", 600))
	if err != nil {
		t.Fatal(err)
	}
	defer answer.Abort()
	for round := range 2 {
		before := sourceReuseInspect(m, backend, resolver)
		candidate, err := m.PrepareUnchangedRanges(context.Background(), v4, v6)
		if err != nil {
			t.Fatal(err)
		}
		store := sourceReuseBorrow(t, candidate, v4, v6)
		if candidate.namespace != before.selected || candidate.base != before.selected ||
			candidate.persistent != nil || candidate.initial != nil || !candidate.UnchangedSelection() {
			t.Fatal("unchanged preparation created or substituted a namespace participant")
		}
		sourceReuseRequireInventory(t, before, m, backend, resolver)
		publishMigration(t, candidate)
		if err := candidate.WaitPersistence(context.Background()); err != nil {
			t.Fatal(err)
		}
		sourceReuseRequireInventory(t, before, m, backend, resolver)
		sourceReuseRequireMapping(t, m, address, "retained-source.example")
		// A new candidate permit actually opens, even though the namespace,
		// backend object and original journal link did not change.
		issued, err := store.Create(fmt.Sprintf("candidate-%d.example", round), round == 1)
		if err != nil {
			t.Fatal("committed unchanged candidate did not receive its own answer permit", err)
		}
		sourceReuseRequireMapping(t, m, issued, fmt.Sprintf("candidate-%d.example", round))
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	answer.Delivered(m.now())
	sourceReuseRequireMapping(t, m, address, "retained-source.example")
}

func TestSourceUnchangedRangeMismatchRefusesBeforeAllocation(t *testing.T) {
	m, backend, resolver, v4, v6 := sourceReuseSelected(t)
	for _, test := range []struct {
		name string
		v4   netip.Prefix
		v6   netip.Prefix
	}{
		{"different-v4", netip.MustParsePrefix("198.19.0.0/29"), v6},
		{"different-v6", v4, netip.MustParsePrefix("fd00::/125")},
		{"remove-v6", v4, netip.Prefix{}},
		{"remove-v4", netip.Prefix{}, v6},
		{"remove-both", netip.Prefix{}, netip.Prefix{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := sourceReuseInspect(m, backend, resolver)
			candidate, err := m.PrepareUnchangedRanges(context.Background(), test.v4, test.v6)
			if candidate != nil {
				candidate.Abort()
				t.Fatal("range mismatch returned an allocation-capable candidate")
			}
			if err == nil {
				t.Fatal("different ranges were accepted as unchanged")
			}
			sourceReuseRequireInventory(t, before, m, backend, resolver)
		})
	}
	// A refusal must not poison the real matching path.
	before := sourceReuseInspect(m, backend, resolver)
	candidate, err := m.PrepareUnchangedRanges(context.Background(), v4, v6)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(candidate.Abort)
	publishMigration(t, candidate)
	sourceReuseRequireInventory(t, before, m, backend, resolver)
}

func TestSourceUnchangedCandidateCannotCrossARealPersistentWinner(t *testing.T) {
	m, backend, resolver, v4, v6 := sourceReuseSelected(t)
	address, err := m.create("old-answer.example", false)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := m.ProtectAnswer(fakeAnswer(address, "old-answer.example", 600))
	if err != nil {
		t.Fatal(err)
	}
	defer answer.Abort()
	stale, err := m.PrepareUnchangedRanges(context.Background(), v4, v6)
	if err != nil {
		t.Fatal(err)
	}
	store := sourceReuseBorrow(t, stale, v4, v6)
	options := fixtureOptions(backend, resolver, "real-winner")
	options.Backend = backend
	winner, err := m.PreparePersistentRanges(context.Background(), netip.MustParsePrefix("198.19.0.0/29"), v6, options)
	if err != nil {
		t.Fatal(err)
	}
	sourceReusePublishDurable(t, winner)
	before := sourceReuseInspect(m, backend, resolver)
	if before.selected == stale.base || winner.persistent == nil || winner.persistent.acknowledged {
		t.Fatal("fixture did not publish a distinct genuine participant with an outstanding ACK")
	}
	if fence, _, err := stale.PrepareCommit(); fence != nil || !errors.Is(err, ErrMigrationStale) {
		if fence != nil {
			fence.Abort()
			stale.ActivatePersistence()
		}
		t.Fatal("stale unchanged candidate crossed another selected base", err)
	}
	if _, err := store.Create("stale-candidate.example", false); !errors.Is(err, ErrCandidateNotCommitted) {
		t.Fatal("stale candidate permit issued an answer", err)
	}
	stale.Abort()
	stale.ActivatePersistence()
	sourceReuseRequireInventory(t, before, m, backend, resolver)
	if winner.persistent.acknowledged {
		t.Fatal("stale source cleanup silently acknowledged the winner's real participant")
	}
	sourceReuseRequireMapping(t, m, address, "old-answer.example")
	answer.Delivered(m.now())
	sourceReuseRequireMapping(t, m, address, "old-answer.example")
	if err := winner.AcknowledgePersistence(context.Background(), "wrong-effective-owner"); !errors.Is(err, ErrPersistenceIdentity) {
		t.Fatal("unrelated owner acknowledged the winner", err)
	}
	if winner.persistent.acknowledged {
		t.Fatal("rejected acknowledgement cleared the real winner's debt")
	}
	if err := winner.AcknowledgePersistence(context.Background(), options.EffectiveConfigurationID); err != nil {
		t.Fatal(err)
	}
	if !winner.persistent.acknowledged {
		t.Fatal("exact winner acknowledgement did not settle its own participant")
	}
}

func TestSourceUnchangedCancellationAndManagerStopKeepAdmissionClosed(t *testing.T) {
	m, backend, resolver, v4, v6 := sourceReuseSelected(t)
	before := sourceReuseInspect(m, backend, resolver)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if candidate, err := m.PrepareUnchangedRanges(ctx, v4, v6); candidate != nil || !errors.Is(err, context.Canceled) {
		if candidate != nil {
			candidate.Abort()
		}
		t.Fatal("canceled unchanged preparation was admitted", err)
	}
	sourceReuseRequireInventory(t, before, m, backend, resolver)
	candidate, err := m.PrepareUnchangedRanges(context.Background(), v4, v6)
	if err != nil {
		t.Fatal(err)
	}
	store := sourceReuseBorrow(t, candidate, v4, v6)
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !m.work.Sealed() {
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("actual Manager.Close did not seal admission")
		}
	}
	select {
	case err := <-closed:
		t.Fatal("Close failed to retain the already prepared candidate until its terminal", err)
	default:
	}
	if late, err := m.PrepareUnchangedRanges(context.Background(), v4, v6); late != nil || !errors.Is(err, lifecycle.ErrStopped) {
		if late != nil {
			late.Abort()
		}
		t.Fatal("Stop admitted another unchanged candidate", err)
	}
	if fence, _, err := candidate.PrepareCommit(); fence != nil || !errors.Is(err, ErrMigrationStale) {
		if fence != nil {
			fence.Abort()
			candidate.ActivatePersistence()
		}
		t.Fatal("prepared candidate published after actual Stop seal", err)
	}
	sourceReuseRequireInventory(t, before, m, backend, resolver)
	candidate.Abort()
	candidate.ActivatePersistence()
	if _, err := store.Create("stopped-candidate.example", false); !errors.Is(err, ErrCandidateNotCommitted) {
		t.Fatal("aborted Stop candidate opened its permit", err)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not join after the actual candidate terminal")
	}
}

func TestSourceUnchangedEmptySelectionPreservesRemovedRangeRecognition(t *testing.T) {
	m, backend, resolver, _, _ := sourceReuseSelected(t)
	address, err := m.create("pre-removal.example", false)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := m.ProtectAnswer(fakeAnswer(address, "pre-removal.example", 600))
	if err != nil {
		t.Fatal(err)
	}
	defer answer.Abort()
	answer.Delivered(m.now())
	options := fixtureOptions(backend, resolver, "real-removal")
	removal, err := m.PreparePersistentRemoval(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	sourceReusePublishDurable(t, removal)
	if err := removal.AcknowledgePersistence(context.Background(), options.EffectiveConfigurationID); err != nil {
		t.Fatal(err)
	}
	if !m.active.empty {
		t.Fatal("real removal did not select an empty allocator")
	}
	for range 2 {
		before := sourceReuseInspect(m, backend, resolver)
		candidate, err := m.PrepareUnchangedSelection(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		store := sourceReuseBorrow(t, candidate, netip.Prefix{}, netip.Prefix{})
		if candidate.namespace != before.selected || candidate.base != before.selected ||
			candidate.persistent != nil || candidate.initial != nil || !candidate.UnchangedSelection() {
			t.Fatal("disabled source refresh substituted an allocator or a removal transaction")
		}
		publishMigration(t, candidate)
		sourceReuseRequireInventory(t, before, m, backend, resolver)
		if _, err := store.Create("disabled-source.example", false); !errors.Is(err, ErrNoActiveNamespace) {
			t.Fatal("disabled source reuse activated an allocator", err)
		}
		sourceReuseRequireMapping(t, m, address, "pre-removal.example")
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
