package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

// These fixtures model transactions and barriers in memory. They do not open a
// database, call a native resolver, or claim filesystem durability coverage.
type runtimeFixtureBackend struct {
	adapter.FakeIPRuntimeBackend
	access sync.Mutex
	descriptor adapter.FakeIPRuntimeBackendDescriptor
	generation uint64
	namespaces map[string]*runtimeFixtureNamespace
	links map[string]adapter.FakeIPRuntimeLink
	deadlines map[uint64]time.Time
	highToken uint64
	counters adapter.FakeIPRuntimeCounters
	counterCalls int
	observeBarrier func()
	prepareBarrier func()
	failLink bool
	observed int
	reclaims int
	linkRemovals int
	authority map[netip.Addr]adapter.FakeIPRuntimeAnswer
}
func fixtureBackend(id string) *runtimeFixtureBackend {
	return &runtimeFixtureBackend{descriptor: adapter.FakeIPRuntimeBackendDescriptor{Path: "/fixture/"+id, DatabaseID: id}, authority: make(map[netip.Addr]adapter.FakeIPRuntimeAnswer), namespaces: make(map[string]*runtimeFixtureNamespace), links: make(map[string]adapter.FakeIPRuntimeLink), deadlines: make(map[uint64]time.Time)}
}
func (b *runtimeFixtureBackend) RuntimeDescriptor(context.Context) (adapter.FakeIPRuntimeBackendDescriptor, error) { return b.descriptor, nil }
func (b *runtimeFixtureBackend) ReserveFakeIPRuntimeCounters(_ context.Context, minimum adapter.FakeIPRuntimeCounters, count uint64) (floor, ceiling adapter.FakeIPRuntimeCounters, err error) {
	b.access.Lock(); defer b.access.Unlock(); b.counterCalls++; floor = b.counters; floor.Revision = max(floor.Revision, minimum.Revision); floor.Token = max(floor.Token, minimum.Token)
	if floor.Revision > ^uint64(0)-count || floor.Token > ^uint64(0)-count { return floor, ceiling, ErrPersistenceIdentity }
	ceiling = adapter.FakeIPRuntimeCounters{Revision: floor.Revision+count, Token: floor.Token+count}; b.counters = ceiling; return
}
func (b *runtimeFixtureBackend) RetainFakeIPRuntimeAuthority(_ context.Context, records []adapter.FakeIPRuntimeAnswer) error {
 b.access.Lock(); defer b.access.Unlock()
 for _,record:=range records { old,found:=b.authority[record.Address]; if found&&old.Revision>record.Revision { continue }; if found&&old.Revision==record.Revision { if old.Domain!=record.Domain { return ErrRecoveryConflict }; record.Superseded=record.Superseded||old.Superseded }; record.Obsolete=true; record.Pending=0; record.Token=0; record.PendingTTL=0; record.ExpiresAt=time.Time{}; b.authority[record.Address]=record }; return nil
}
func (b *runtimeFixtureBackend) FakeIPRuntimeAuthority(context.Context) ([]adapter.FakeIPRuntimeAnswer,error) { b.access.Lock(); defer b.access.Unlock(); var records []adapter.FakeIPRuntimeAnswer; for _,record:=range b.authority { records=append(records,record) }; return records,nil }
func (b *runtimeFixtureBackend) PruneFakeIPRuntimeAuthority(_ context.Context, ranges []netip.Prefix) error { b.access.Lock(); defer b.access.Unlock(); for address:=range b.authority { retained:=false; for _,prefix:=range ranges { if prefix.Contains(address) { retained=true; break } }; if !retained { delete(b.authority,address) } }; return nil }
func (b *runtimeFixtureBackend) AllocateFakeIPGeneration(context.Context) (uint64, error) {
	b.access.Lock(); defer b.access.Unlock(); if b.generation == ^uint64(0) { return 0, ErrPersistenceIdentity }; b.generation++; return b.generation, nil
}
func (b *runtimeFixtureBackend) SnapshotFakeIP(context.Context) (adapter.FakeIPStorageSnapshot, error) { return adapter.FakeIPStorageSnapshot{Mappings: make(map[netip.Addr]string)}, nil }
func (b *runtimeFixtureBackend) PrepareFakeIPNamespace(_ context.Context, d adapter.FakeIPRuntimeNamespaceDescriptor, image adapter.FakeIPStorageSnapshot) (adapter.FakeIPRuntimeNamespace, error) {
	if b.prepareBarrier != nil { b.prepareBarrier() }
	b.access.Lock(); defer b.access.Unlock()
	if b.namespaces[d.ID] != nil { return nil, ErrPersistenceIdentity }
	n := &runtimeFixtureNamespace{MemoryStorage: NewMemoryStorage(), backend: b, descriptor: d, answers: make(map[netip.Addr]adapter.FakeIPRuntimeAnswer), tokens: make(map[fixtureToken]adapter.FakeIPRuntimeAnswer)}
	if image.Metadata != nil { n.metadata = *image.Metadata }
	for address, domain := range image.Mappings { _ = n.MemoryStorage.FakeIPStore(address, domain) }
	for _, answer := range image.Answers { n.answers[answer.Address] = answer }
	for _, token := range image.PendingAnswers { n.tokens[fixtureToken{token.Token, token.Address}] = token }
	b.namespaces[d.ID] = n; return n, nil
}
func (b *runtimeFixtureBackend) OpenFakeIPNamespace(_ context.Context, id string) (adapter.FakeIPRuntimeNamespace, error) { b.access.Lock(); defer b.access.Unlock(); n := b.namespaces[id]; if n == nil { return nil, ErrPersistenceIdentity }; return n, nil }
func (b *runtimeFixtureBackend) FakeIPRuntimeCatalog(context.Context) (adapter.FakeIPRuntimeCatalog, error) {
	b.access.Lock(); defer b.access.Unlock(); var c adapter.FakeIPRuntimeCatalog
	ids := make([]string, 0, len(b.namespaces)); for id := range b.namespaces { ids = append(ids, id) }; sort.Strings(ids); for _, id := range ids { c.Namespaces = append(c.Namespaces, b.namespaces[id].descriptor) }; for _, l := range b.links { c.Links = append(c.Links, l) }; return c, nil
}
func (b *runtimeFixtureBackend) ReclaimFakeIPRuntimeOrphans(_ context.Context, anchorID string, allowed []adapter.FakeIPRuntimeNamespaceDescriptor) error { b.access.Lock(); defer b.access.Unlock(); keep:=make(map[adapter.FakeIPRuntimeNamespaceDescriptor]bool); for _, d:=range allowed { keep[d]=true }; b.reclaims++; for id,n:=range b.namespaces { if n.descriptor.AnchorDatabaseID == anchorID && !keep[n.descriptor] { delete(b.namespaces,id) } }; return nil }
func (b *runtimeFixtureBackend) SaveFakeIPRuntimeLink(_ context.Context, l adapter.FakeIPRuntimeLink) error {
	b.access.Lock(); defer b.access.Unlock(); if b.failLink { return errors.New("injected participant link failure") }
	if old, found := b.links[l.ID]; found { if !sameRuntimeLink(old, l) { return ErrPersistenceIdentity }; l.DiscoveryReady = l.DiscoveryReady || old.DiscoveryReady; l.Acknowledged = l.Acknowledged || old.Acknowledged }
	b.links[l.ID] = l; return nil
}
func (b *runtimeFixtureBackend) RemoveFakeIPRuntimeLink(_ context.Context, id string) error { b.access.Lock(); b.linkRemovals++; delete(b.links, id); b.access.Unlock(); return nil }
func (b *runtimeFixtureBackend) ResolveFakeIPPendingExpiries(_ context.Context, tokens []adapter.FakeIPRuntimeAnswer, now time.Time) (map[uint64]time.Time, uint64, error) {
	b.access.Lock(); defer b.access.Unlock(); ttl := make(map[uint64]uint32); for _, token := range tokens { ttl[token.Token] = max(ttl[token.Token], token.PendingTTL); b.highToken = max(b.highToken, token.Token) }
	result := make(map[uint64]time.Time); for id, seconds := range ttl { at, found := b.deadlines[id]; if !found { at = now.Add(time.Duration(seconds)*time.Second); b.deadlines[id] = at }; result[id] = at }; return result, b.highToken, nil
}
func (b *runtimeFixtureBackend) ReleaseFakeIPPendingExpiries(_ context.Context, ids []uint64) error { b.access.Lock(); defer b.access.Unlock(); for _, id := range ids { delete(b.deadlines, id) }; return nil }

type fixtureToken struct { token uint64; address netip.Addr }
type runtimeFixtureNamespace struct {
	*MemoryStorage
	access sync.Mutex
	backend *runtimeFixtureBackend
	descriptor adapter.FakeIPRuntimeNamespaceDescriptor
	metadata adapter.FakeIPMetadata
	answers map[netip.Addr]adapter.FakeIPRuntimeAnswer
	tokens map[fixtureToken]adapter.FakeIPRuntimeAnswer
	issued bool
	recoverFailure bool
}
func (n *runtimeFixtureNamespace) Descriptor() adapter.FakeIPRuntimeNamespaceDescriptor { return n.descriptor }
func (n *runtimeFixtureNamespace) FakeIPMetadata() *adapter.FakeIPMetadata { n.access.Lock(); defer n.access.Unlock(); v := n.metadata; return &v }
func (n *runtimeFixtureNamespace) FakeIPSaveMetadata(v *adapter.FakeIPMetadata) error { n.access.Lock(); n.metadata = *v; n.access.Unlock(); return nil }
func (n *runtimeFixtureNamespace) SnapshotAllocation() adapter.FakeIPStorageSnapshot {
	image := adapter.FakeIPStorageSnapshot{Metadata: n.FakeIPMetadata(), Mappings: make(map[netip.Addr]string)}
	n.addressAccess.RLock(); for address, domain := range n.addressCache { image.Mappings[address] = domain }; n.addressAccess.RUnlock(); return image
}
func (n *runtimeFixtureNamespace) Snapshot(context.Context) (adapter.FakeIPStorageSnapshot, error) {
	image := n.SnapshotAllocation(); n.access.Lock(); defer n.access.Unlock(); image.Issued = n.issued
	for _, answer := range n.answers { image.Answers = append(image.Answers, answer) }; for _, token := range n.tokens { image.PendingAnswers = append(image.PendingAnswers, token) }; return image, nil
}
func (n *runtimeFixtureNamespace) Flush(context.Context) error { return nil }
func (n *runtimeFixtureNamespace) QueueAuthority(next adapter.FakeIPRuntimeAnswer) { n.access.Lock(); defer n.access.Unlock(); old := n.answers[next.Address]; if next.Revision > old.Revision { n.answers[next.Address] = next } }
func (n *runtimeFixtureNamespace) Observe(_ context.Context, requested []adapter.FakeIPRuntimeAnswer) error {
	if n.backend.observeBarrier != nil { n.backend.observeBarrier() }
	n.backend.access.Lock(); n.backend.observed++; n.backend.access.Unlock()
	n.access.Lock(); defer n.access.Unlock(); n.issued = true
	for _, request := range requested { key := fixtureToken{request.Token, request.Address}; if _, exists := n.tokens[key]; exists { continue }; current := n.answers[request.Address]; if current.Revision != request.Revision || current.Domain != request.Domain { current = request; current.Token, current.Pending = 0, 0 }; current.Obsolete, current.Superseded = false, false; current.Pending++; current.PendingTTL = max(current.PendingTTL, request.PendingTTL); n.answers[request.Address] = current; n.tokens[key] = request }; return nil
}
func (n *runtimeFixtureNamespace) Complete(_ context.Context, requested []adapter.FakeIPRuntimeAnswer, at time.Time, delivered bool) error {
	n.access.Lock(); defer n.access.Unlock()
	for _, request := range requested { key := fixtureToken{request.Token, request.Address}; if _, exists := n.tokens[key]; !exists { continue }; delete(n.tokens, key); current := n.answers[request.Address]; if current.Revision != request.Revision { continue }; if current.Pending != 0 { current.Pending-- }; if delivered && !current.Obsolete { expires := at.Add(time.Duration(request.PendingTTL)*time.Second); if expires.After(current.ExpiresAt) { current.ExpiresAt = expires } }; n.answers[request.Address] = current }; return nil
}
func (n *runtimeFixtureNamespace) Recover(ctx context.Context, now time.Time) ([]adapter.FakeIPRuntimeAnswer, error) { return n.RecoverWithDeadlines(ctx, now, nil) }
func (n *runtimeFixtureNamespace) RecoverWithDeadlines(_ context.Context, now time.Time, deadlines map[uint64]time.Time) ([]adapter.FakeIPRuntimeAnswer, error) {
	n.access.Lock(); defer n.access.Unlock(); if n.recoverFailure { n.recoverFailure = false; return nil, errors.New("interrupted namespace recovery") }
	for _, token := range n.tokens { answer := n.answers[token.Address]; if token.Revision != answer.Revision { continue }; expiry := deadlines[token.Token]; if deadlines == nil { expiry = now.Add(time.Duration(token.PendingTTL)*time.Second) }; if expiry.After(answer.ExpiresAt) { answer.ExpiresAt = expiry }; answer.Pending = 0; n.answers[token.Address] = answer }
	n.tokens = make(map[fixtureToken]adapter.FakeIPRuntimeAnswer)
	var result []adapter.FakeIPRuntimeAnswer; for address, answer := range n.answers { if !answer.ExpiresAt.After(now) { answer.Obsolete = true; n.answers[address] = answer }; result = append(result, answer) }; return result, nil
}
func (n *runtimeFixtureNamespace) Invalidate(_ context.Context, ids []adapter.FakeIPRuntimeAnswer) error { n.access.Lock(); defer n.access.Unlock(); for _, id := range ids { current := n.answers[id.Address]; if current.Revision == id.Revision { current.Obsolete, current.Superseded = true, true; current.Pending = 0; n.answers[id.Address] = current } }; return nil }
func (n *runtimeFixtureNamespace) Abort(ctx context.Context) error { n.access.Lock(); issued := n.issued; n.access.Unlock(); if issued { return ErrPersistencePending }; return n.Reclaim(ctx) }
func (n *runtimeFixtureNamespace) Reclaim(context.Context) error { n.backend.access.Lock(); delete(n.backend.namespaces, n.descriptor.ID); n.backend.access.Unlock(); return nil }

type runtimeFixtureResolver struct { access sync.Mutex; backends map[adapter.FakeIPRuntimeBackendDescriptor]*runtimeFixtureBackend; references int; requested []adapter.FakeIPRuntimeBackendDescriptor }
func fixtureResolver(backends ...*runtimeFixtureBackend) *runtimeFixtureResolver { r := &runtimeFixtureResolver{backends: make(map[adapter.FakeIPRuntimeBackendDescriptor]*runtimeFixtureBackend)}; for _, b := range backends { r.backends[b.descriptor] = b }; return r }
func (r *runtimeFixtureResolver) ResolveFakeIPRuntime(_ context.Context, d adapter.FakeIPRuntimeBackendDescriptor) (adapter.FakeIPRuntimeBackend, func() error, error) {
	r.access.Lock(); r.requested = append(r.requested, d); b := r.backends[d]; if b == nil { r.access.Unlock(); return nil, nil, ErrRecoveryAnchorRequired }; r.references++; r.access.Unlock()
	var once sync.Once; return b, func() error { once.Do(func() { r.access.Lock(); r.references--; r.access.Unlock() }); return nil }, nil
}
func fixtureEmptyManager(t *testing.T) *Manager { t.Helper(); m := NewEmptyManager(context.Background(), log.NewNOPFactory().Logger()); if err := m.Start(); err != nil { t.Fatal(err) }; t.Cleanup(func() { _ = m.Close() }); return m }
func fixtureOptions(b *runtimeFixtureBackend, r *runtimeFixtureResolver, id string) PersistentMigrationOptions { return PersistentMigrationOptions{Anchor: b, Resolver: r, TransactionID: id, EffectiveConfigurationID: "effective/"+id} }
func waitFixture(t *testing.T, channel <-chan struct{}) { t.Helper(); select { case <-channel: case <-time.After(5*time.Second): t.Fatal("barrier did not complete") } }

func TestDurableCancellationReopensOldAdmissionBeforePrivateWriterEnds(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29")
	address, _ := m.create("old.example", false)
	b := fixtureBackend("anchor"); r := fixtureResolver(b)
	entered, release := make(chan struct{}), make(chan struct{}); var enterOnce, releaseOnce sync.Once
	b.prepareBarrier = func() { enterOnce.Do(func() { close(entered); <-release }) }; t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	c, err := m.PreparePersistentRanges(context.Background(), netip.MustParsePrefix("198.19.0.0/29"), netip.Prefix{}, fixtureOptions(b, r, "cancel")); if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background()); result := make(chan error, 1)
	go func() { _, _, err := c.PrepareDurableCommit(ctx); result <- err }(); waitFixture(t, entered); cancel()
	if err := <-result; !errors.Is(err, context.Canceled) { t.Fatal(err) }
	answer, err := m.ProtectAnswer(fakeAnswer(address, "old.example", 60)); if err != nil { t.Fatal("old admission stayed closed", err) }; answer.Abort()
	if _, err = m.create("ongoing.example", false); err != nil { t.Fatal("Create blocked by private I/O", err) }
	select { case <-c.persistent.finished: t.Fatal("cancellation falsely joined private writer"); default: }
	r.access.Lock(); retained := r.references; r.access.Unlock(); if retained == 0 { t.Fatal("private backend dependency released early") }
	releaseOnce.Do(func() { close(release) }); if err := c.WaitPersistence(context.Background()); err != nil { t.Fatal(err) }
	if c.permit.admitted() || m.store.inet4Range != netip.MustParsePrefix("198.18.0.0/29") { t.Fatal("late writer published canceled candidate") }
	r.access.Lock(); retained = r.references; r.access.Unlock(); if retained != 0 { t.Fatal("terminal aborted writer retained backend forever") }
}

func TestPendingCompletionTransfersExactlyOnceAndActivatesAfterFence(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29"); now := time.Unix(100, 0); m.now = func() time.Time { return now }
	address, _ := m.create("pending.example", false); answer, err := m.ProtectAnswer(fakeAnswer(address, "pending.example", 321)); if err != nil { t.Fatal(err) }
	b := fixtureBackend("anchor"); r := fixtureResolver(b); entered, release := make(chan struct{}), make(chan struct{}); var once sync.Once
	b.prepareBarrier = func() { once.Do(func() { close(entered); <-release }) }
	c, err := m.PreparePersistentRanges(context.Background(), netip.MustParsePrefix("198.19.0.0/29"), netip.Prefix{}, fixtureOptions(b, r, "transfer")); if err != nil { t.Fatal(err) }
	result := make(chan *RangeCommit, 1); failures := make(chan error, 1)
	go func() { fence, _, err := c.PrepareDurableCommit(context.Background()); if err != nil { failures <- err; return }; result <- fence }()
	waitFixture(t, entered); now = now.Add(time.Hour); answer.Delivered(now); answer.Abort(); close(release)
	var fence *RangeCommit; select { case fence = <-result: case err := <-failures: t.Fatal(err) }
	fence.Publish(); fence.Publish(); fence.Abort()
	select { case <-c.persistent.finished: t.Fatal("postpublication worker ran inside publication guard"); default: }
	c.ActivatePersistence(); c.ActivatePersistence(); if err := c.WaitPersistence(context.Background()); err != nil { t.Fatal(err) }
	found := false
	for _, handle := range c.persistent.created { image, err := handle.Snapshot(context.Background()); if err != nil { t.Fatal(err) }; for _, record := range image.Answers { if record.Address == address { found = true; if record.Pending != 0 || !record.ExpiresAt.Equal(now.Add(321*time.Second)) { t.Fatal("exact completion lost or duplicated", record) } } } }
	if !found { t.Fatal("old identity not copied") }
}

func TestUnchangedNamespaceReturnsToBatchPathAfterExactAcknowledgement(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29"); b := fixtureBackend("anchor"); r := fixtureResolver(b); options := fixtureOptions(b, r, "batch")
	c, err := m.PreparePersistentRanges(context.Background(), netip.MustParsePrefix("198.19.0.0/29"), netip.Prefix{}, options); if err != nil { t.Fatal(err) }
	fence, _, err := c.PrepareDurableCommit(context.Background()); if err != nil { t.Fatal(err) }; fence.Publish(); c.ActivatePersistence(); if err = c.WaitPersistence(context.Background()); err != nil { t.Fatal(err) }
	if err = m.AcknowledgePersistence(context.Background(), "wrong"); !errors.Is(err, ErrPersistenceIdentity) { t.Fatal("RAM/source-tag acknowledgement was accepted", err) }
	if err = m.AcknowledgePersistence(context.Background(), options.EffectiveConfigurationID); err != nil { t.Fatal(err) }
	address, err := m.create("batch.example", false); if err != nil { t.Fatal(err) }; answer, err := m.ProtectAnswer(fakeAnswer(address, "batch.example", 60)); if err != nil { t.Fatal(err) }; answer.Delivered(time.Now())
	b.access.Lock(); observed := b.observed; b.access.Unlock(); if observed != 0 { t.Fatal("normal unchanged namespace performed synchronous answer certification") }
}

func TestIncompleteAndPeerOnlyReadyLinksCannotAuthorizeDiscovery(t *testing.T) {
	anchor, peer, missing := fixtureBackend("anchor"), fixtureBackend("peer"), fixtureBackend("missing")
	link := adapter.FakeIPRuntimeLink{ID: "incomplete", EffectiveConfigurationID: "old", Namespaces: []adapter.FakeIPRuntimeNamespaceDescriptor{{Version: 1, AnchorDatabaseID: anchor.descriptor.DatabaseID, Backend: missing.descriptor, ID: "x", LogicalID: "x", EffectiveConfigurationID: "old"}}}
	anchor.links[link.ID] = link; link.DiscoveryReady = true; peer.links[link.ID] = link
	m := fixtureEmptyManager(t); r := fixtureResolver(anchor, peer)
	if err := m.RecoverPersistent(context.Background(), anchor, r, "explicit-disabled", peer); err != nil { t.Fatal(err) }
	for _, requested := range r.requested { if requested == missing.descriptor { t.Fatal("incomplete/peer-only marker opened an unapproved missing backend") } }
	if err := m.AcknowledgePersistence(context.Background(), "explicit-disabled"); err != nil { t.Fatal(err) }
	if err := m.ReclaimPersistence(context.Background()); err != nil { t.Fatal(err) }
}

func TestRepeatedRecoveryUsesOriginalAbsolutePendingDeadline(t *testing.T) {
	b := fixtureBackend("anchor"); r := fixtureResolver(b); prefix := netip.MustParsePrefix("198.18.0.0/29"); address := prefix.Addr().Next().Next()
	token := adapter.FakeIPRuntimeAnswer{Token: 90, Address: address, Domain: "late.example", Revision: 7, Pending: 1, PendingTTL: 60}
	link := adapter.FakeIPRuntimeLink{ID: "ready", EffectiveConfigurationID: "explicit", DiscoveryReady: true}
	for _, id := range []string{"copy-a", "copy-b"} {
		d := adapter.FakeIPRuntimeNamespaceDescriptor{Version: 1, AnchorDatabaseID: b.descriptor.DatabaseID, Backend: b.descriptor, ID: id, LogicalID: "same", EffectiveConfigurationID: "explicit"}
		_, err := b.PrepareFakeIPNamespace(context.Background(), d, adapter.FakeIPStorageSnapshot{Metadata: &adapter.FakeIPMetadata{Inet4Range: prefix}, Mappings: map[netip.Addr]string{address: token.Domain}, Answers: []adapter.FakeIPRuntimeAnswer{token}, PendingAnswers: []adapter.FakeIPRuntimeAnswer{token}}); if err != nil { t.Fatal(err) }; link.Namespaces = append(link.Namespaces, d)
	}
	b.links[link.ID] = link; b.namespaces["copy-b"].recoverFailure = true
	first := fixtureEmptyManager(t); start := time.Unix(100, 0); first.now = func() time.Time { return start }
	if err := first.RecoverPersistent(context.Background(), b, r, "explicit"); err == nil { t.Fatal("injected partial recovery did not stop") }
	second := fixtureEmptyManager(t); later := start.Add(20*time.Second); second.now = func() time.Time { return later }
	if err := second.RecoverPersistent(context.Background(), b, r, "explicit"); err != nil { t.Fatal(err) }
	if domain, found := second.lookup(address); !found || domain != token.Domain { t.Fatal("valid recognition was lost") }
	for _, record := range second.protection.mappings { if !record.expires.Equal(start.Add(time.Minute)) { t.Fatal("restart extended interrupted answer a second time", record.expires) } }
}

func TestPersistenceExecutorCancelDoesNotJoinStartedOperation(t *testing.T) {
	var worker persistenceExecutor; entered, release := make(chan struct{}), make(chan struct{})
	job, cancel := worker.submit(func() error { close(entered); <-release; return nil }); waitFixture(t, entered)
	if cancel() { t.Fatal("started operation reported canceled completion") }
	queued, cancelQueued := worker.submit(func() error { t.Error("canceled queued job ran"); return nil }); _ = queued
	if !cancelQueued() { t.Fatal("private queued observation was not removable") }
	closed := make(chan struct{}); go func() { worker.close(); close(closed) }()
	select { case <-closed: t.Fatal("worker joined before actual operation return"); default: }
	close(release); if err := <-job.result; err != nil { t.Fatal(err) }; waitFixture(t, closed)
}

func TestRecoveryNewAuthoritySupersedesOldPendingCopyAndRejectsEqualConflict(t *testing.T) {
	for _, equal := range []bool{false, true} { t.Run(map[bool]string{false: "newer-certificate", true: "equal-conflict"}[equal], func(t *testing.T) {
		b := fixtureBackend("anchor"); r := fixtureResolver(b); prefix := netip.MustParsePrefix("198.18.0.0/29"); address := prefix.Addr().Next().Next(); now := time.Unix(100, 0)
		old := adapter.FakeIPRuntimeAnswer{Token: 5, Address: address, Domain: "old.example", Revision: 10, Pending: 1, PendingTTL: 60}
		latest := adapter.FakeIPRuntimeAnswer{Address: address, Domain: "reused.example", Revision: 11, ExpiresAt: now.Add(time.Minute)}; if equal { latest.Revision = old.Revision }
		link := adapter.FakeIPRuntimeLink{ID: "ready", EffectiveConfigurationID: "selected", DiscoveryReady: true}
		for index, answer := range []adapter.FakeIPRuntimeAnswer{old, latest} {
			id := []string{"old", "new"}[index]; d := adapter.FakeIPRuntimeNamespaceDescriptor{Version: 1, AnchorDatabaseID: b.descriptor.DatabaseID, Backend: b.descriptor, ID: id, LogicalID: id, EffectiveConfigurationID: "selected"}
			image := adapter.FakeIPStorageSnapshot{Metadata: &adapter.FakeIPMetadata{Inet4Range: prefix}, Mappings: map[netip.Addr]string{address: answer.Domain}, Answers: []adapter.FakeIPRuntimeAnswer{answer}}; if answer.Pending != 0 { image.PendingAnswers = []adapter.FakeIPRuntimeAnswer{answer} }
			if _, err := b.PrepareFakeIPNamespace(context.Background(), d, image); err != nil { t.Fatal(err) }; link.Namespaces = append(link.Namespaces, d)
		}
		b.links[link.ID] = link; m := fixtureEmptyManager(t); m.now = func() time.Time { return now }
		err := m.RecoverPersistent(context.Background(), b, r, "selected")
		if equal { if !errors.Is(err, ErrRecoveryConflict) { t.Fatal("equal revision conflict reinterpreted", err) }; return }
		if err != nil { t.Fatal(err) }; if domain, found := m.lookup(address); !found || domain != latest.Domain { t.Fatal("old conservative pending certificate stole reused identity") }
		if m.nextAnswerRevision < latest.Revision || m.counterCeiling.Revision <= m.nextAnswerRevision { t.Fatal("global counter reservation was not restored before admission") }
	}) }
}

func TestMemoryFenceActivationAndAbortAreIdempotent(t *testing.T) {
	m := protectionManager(t, "198.18.0.0/29"); candidate, _ := prepareMigration(t, m, "198.19.0.0/29")
	fence, _, err := candidate.PrepareCommit(); if err != nil { t.Fatal(err) }
	fence.Abort(); fence.Abort(); fence.Publish(); candidate.ActivatePersistence(); candidate.ActivatePersistence()
	if candidate.permit.admitted() || m.store.inet4Range != netip.MustParsePrefix("198.18.0.0/29") { t.Fatal("terminal abort was reversed") }
}

func TestParticipantFailureAndCounterOverflowNeverPublishCandidate(t *testing.T) {
 for _, kind := range []string{"participant", "counter", "generation"} { t.Run(kind, func(t *testing.T) {
  m := protectionManager(t, "198.18.0.0/29"); anchor, destination := fixtureBackend("anchor"), fixtureBackend("destination"); resolver := fixtureResolver(anchor, destination)
  options := fixtureOptions(anchor, resolver, kind); options.Backend = destination
  if kind == "participant" { destination.failLink = true }; if kind == "counter" { anchor.counters.Token = ^uint64(0) }; if kind == "generation" { anchor.generation = ^uint64(0) }
  candidate, err := m.PreparePersistentRanges(context.Background(), netip.MustParsePrefix("198.19.0.0/29"), netip.Prefix{}, options); if err != nil { t.Fatal(err) }
  if fence, _, err := candidate.PrepareDurableCommit(context.Background()); err == nil || fence != nil { t.Fatal("failed durable preparation handed out a publication fence") }
  if err := candidate.WaitPersistence(context.Background()); err != nil { t.Fatal(err) }
  if candidate.permit.admitted() || m.active == candidate.namespace { t.Fatal("failed preparation published") }
  for _, link := range anchor.links { if link.DiscoveryReady { t.Fatal("partial participants left an authoritative ready link") } }
  if len(anchor.namespaces) != 0 || len(destination.namespaces) != 0 { t.Fatal("terminal failed candidate kept unused buckets") }
 }) }
}

func TestCounterRefillIsAmortizedAndLegacyNeedsNoAnchor(t *testing.T) {
 m := protectionManager(t, "198.18.0.0/29"); address, err := m.create("same.example", false); if err != nil { t.Fatal(err) }
 answer, err := m.ProtectAnswer(fakeAnswer(address, "same.example", 1)); if err != nil { t.Fatal(err) }; answer.Abort()
 if m.counterRoot != nil { t.Fatal("original allocator required a recovery anchor") }
 anchor := fixtureBackend("anchor"); m.counterRoot = anchor
 for range reservedAddressCount+1 { answer, err = m.ProtectAnswer(fakeAnswer(address, "same.example", 1)); if err != nil { t.Fatal(err) }; answer.Abort() }
 if anchor.counterCalls != 2 { t.Fatal("counter reservation performed per-answer durability", anchor.counterCalls) }
}

func TestContinuousCreateDuringSnapshotNeedsNoTrafficQuiescence(t *testing.T) {
 m := protectionManager(t, "198.18.0.0/29"); anchor := fixtureBackend("anchor"); resolver := fixtureResolver(anchor)
 entered, release := make(chan struct{}), make(chan struct{}); var once sync.Once
 anchor.prepareBarrier = func() { once.Do(func() { close(entered); <-release }) }
 candidate, err := m.PreparePersistentRanges(context.Background(), netip.MustParsePrefix("198.19.0.0/29"), netip.Prefix{}, fixtureOptions(anchor, resolver, "traffic")); if err != nil { t.Fatal(err) }
 result := make(chan persistentResult, 1); go func() { fence, impact, err := candidate.PrepareDurableCommit(context.Background()); result <- persistentResult{fence, impact, err} }(); waitFixture(t, entered)
 for i := range 100 { if _, err := m.create("traffic-"+strconv.Itoa(i)+".example", false); err != nil { t.Fatal(err) } }
 close(release); prepared := <-result; if prepared.err != nil { t.Fatal(prepared.err) }; prepared.commit.Publish(); candidate.ActivatePersistence(); if err := candidate.WaitPersistence(context.Background()); err != nil { t.Fatal(err) }
}

func TestCanceledStartedAnswerWriterRetainsExactLeaseUntilCompletion(t *testing.T) {
 m := protectionManager(t, "198.18.0.0/29"); anchor := fixtureBackend("anchor"); resolver := fixtureResolver(anchor)
 candidate, err := m.PreparePersistentRanges(context.Background(), netip.MustParsePrefix("198.19.0.0/29"), netip.Prefix{}, fixtureOptions(anchor, resolver, "answer")); if err != nil { t.Fatal(err) }
 fence, _, err := candidate.PrepareDurableCommit(context.Background()); if err != nil { t.Fatal(err) }; fence.Publish(); candidate.ActivatePersistence(); if err = candidate.WaitPersistence(context.Background()); err != nil { t.Fatal(err) }
 entered, release := make(chan struct{}), make(chan struct{}); var once sync.Once
 anchor.observeBarrier = func() { once.Do(func() { close(entered); <-release }) }
 address, _ := m.create("waiting.example", false); ctx, cancel := context.WithCancel(context.Background()); result := make(chan error, 1)
 go func() { _, err := m.ProtectAnswerContext(ctx, fakeAnswer(address, "waiting.example", 60)); result <- err }(); waitFixture(t, entered); cancel()
 if err := <-result; !errors.Is(err, context.Canceled) { t.Fatal(err) }
 m.mappingAccess.Lock(); retained := len(m.pendingAnswers); m.mappingAccess.Unlock(); if retained != 1 { t.Fatal("cancellation falsely completed started storage access", retained) }
 changed := m.PersistenceChanged(); close(release)
 waitCtx, stop := context.WithTimeout(context.Background(), 5*time.Second); defer stop()
 for { m.mappingAccess.Lock(); retained = len(m.pendingAnswers); m.mappingAccess.Unlock(); if retained == 0 { break }; if err := m.WaitPersistenceChange(waitCtx, changed); err != nil { t.Fatal(err) }; changed = m.PersistenceChanged() }
}

func TestPersistentRemovalPreservesOldAnswersAcrossBackendChange(t *testing.T) {
 m := protectionManager(t, "198.18.0.0/29"); old, err := m.Borrow(netip.MustParsePrefix("198.18.0.0/29"), netip.Prefix{}); if err != nil { t.Fatal(err) }; defer old.Close()
 address, _ := old.Create("retained.example", false); answer, err := m.ProtectAnswer(fakeAnswer(address, "retained.example", 3600)); if err != nil { t.Fatal(err) }; answer.Delivered(time.Now())
 anchor, destination := fixtureBackend("anchor"), fixtureBackend("new-path"); resolver := fixtureResolver(anchor, destination); options := fixtureOptions(anchor, resolver, "disabled"); options.Backend = destination
 candidate, err := m.PreparePersistentRemoval(context.Background(), options); if err != nil { t.Fatal(err) }
 fence, _, err := candidate.PrepareDurableCommit(context.Background()); if err != nil { t.Fatal(err) }; fence.Publish(); candidate.ActivatePersistence(); if err := candidate.WaitPersistence(context.Background()); err != nil { t.Fatal(err) }
 if _, err := m.create("disabled.example", false); !errors.Is(err, ErrNoActiveNamespace) { t.Fatal("empty allocator issued an address", err) }
 if domain, found := m.lookup(address); !found || domain != "retained.example" { t.Fatal("removal lost valid recognition") }
 if _, err := old.Create("old-tail.example", false); err != nil { t.Fatal("retained old graph lost its permitted allocator", err) }
 if err := m.AcknowledgePersistence(context.Background(), options.EffectiveConfigurationID); err != nil { t.Fatal(err) }
 if len(destination.namespaces) != 0 { t.Fatal("removal initialized an unused destination allocator") }
}

func TestReadyMissingNamespaceAndReusedDatabaseIdentityFailRecovery(t *testing.T) {
 for _, reused := range []bool{false, true} { t.Run(map[bool]string{false:"missing-namespace", true:"different-database"}[reused], func(t *testing.T) {
  anchor, peer := fixtureBackend("anchor"), fixtureBackend("peer"); resolver := fixtureResolver(anchor, peer)
  descriptor := adapter.FakeIPRuntimeNamespaceDescriptor{Version: 1, AnchorDatabaseID: anchor.descriptor.DatabaseID, Backend: peer.descriptor, ID: "required", LogicalID: "required", EffectiveConfigurationID: "selected"}
  anchor.links["ready"] = adapter.FakeIPRuntimeLink{ID:"ready", EffectiveConfigurationID:"selected", DiscoveryReady:true, Namespaces:[]adapter.FakeIPRuntimeNamespaceDescriptor{descriptor}}
  if reused { replacement := fixtureBackend("replacement"); replacement.descriptor.Path = peer.descriptor.Path; resolver.backends[peer.descriptor] = replacement }
  m := fixtureEmptyManager(t)
  if err := m.RecoverPersistent(context.Background(), anchor, resolver, "selected"); !errors.Is(err, ErrPersistenceIdentity) { t.Fatal("missing or replaced identity silently ignored", err) }
 }) }
}

func TestEqualRevisionExpiryCopyDoesNotEraseDeliveryButSupersessionDoes(t *testing.T) {
 address:=netip.MustParseAddr("198.18.0.2"); expired:=adapter.FakeIPRuntimeAnswer{Address:address,Domain:"same.example",Revision:20,Obsolete:true}
 delivered:=expired; delivered.Obsolete=false; delivered.ExpiresAt=time.Unix(100,0)
 merged,err:=mergeRecoveredIdentity(expired,delivered); if err!=nil || merged.Obsolete || !merged.ExpiresAt.Equal(delivered.ExpiresAt) { t.Fatal("expired copy erased same-identity later delivery",err) }
 expired.Superseded=true; merged,err=mergeRecoveredIdentity(expired,delivered); if err!=nil || !merged.Obsolete { t.Fatal("exact reused identity was revived by an older pending copy",err) }
}

func TestIncompleteDiscoveryDoesNotReclaimOwnOrForeignData(t *testing.T) {
 anchor,peer:=fixtureBackend("anchor"),fixtureBackend("peer")
 own:=adapter.FakeIPRuntimeNamespaceDescriptor{Version:1,AnchorDatabaseID:"anchor",Backend:peer.descriptor,ID:"orphan",LogicalID:"orphan",EffectiveConfigurationID:"selected"}
 foreign:=own; foreign.ID="foreign"; foreign.AnchorDatabaseID="other-root"
 image:=adapter.FakeIPStorageSnapshot{Metadata:new(adapter.FakeIPMetadata)}
 if _,err:=peer.PrepareFakeIPNamespace(context.Background(),own,image); err!=nil { t.Fatal(err) }
 if _,err:=peer.PrepareFakeIPNamespace(context.Background(),foreign,image); err!=nil { t.Fatal(err) }
 missing:=own; missing.ID="missing"
 anchor.links["ready"]=adapter.FakeIPRuntimeLink{ID:"ready",EffectiveConfigurationID:"selected",DiscoveryReady:true,Namespaces:[]adapter.FakeIPRuntimeNamespaceDescriptor{missing}}
 m:=fixtureEmptyManager(t)
 if err:=m.RecoverPersistent(context.Background(),anchor,fixtureResolver(anchor,peer),"selected",peer); !errors.Is(err,ErrPersistenceIdentity) { t.Fatal("missing namespace accepted",err) }
 if anchor.reclaims!=0||peer.reclaims!=0||anchor.linkRemovals!=0||peer.linkRemovals!=0||len(peer.namespaces)!=2||len(anchor.deadlines)!=0 { t.Fatal("failed discovery performed cleanup or deadline writes") }
 // With complete discovery, only this root's unlinked namespace can go.
 delete(anchor.links,"ready")
 peer.links["foreign"]=adapter.FakeIPRuntimeLink{ID:"foreign",EffectiveConfigurationID:"other",Namespaces:[]adapter.FakeIPRuntimeNamespaceDescriptor{foreign}}
 next:=fixtureEmptyManager(t)
 if err:=next.RecoverPersistent(context.Background(),anchor,fixtureResolver(anchor,peer),"selected",peer); err!=nil { t.Fatal(err) }
 if peer.namespaces[own.ID]!=nil||peer.namespaces[foreign.ID]==nil { t.Fatal("orphan ownership was not isolated") }
 if _,found:=peer.links["foreign"]; !found { t.Fatal("foreign incomplete link was removed") }
}

func TestUnknownNamespaceFormatAndMixedAnchorLinkAreReadOnlyFailures(t *testing.T) {
 for _,mixed:=range []bool{false,true} { t.Run(strconv.FormatBool(mixed),func(t *testing.T) {
  anchor:=fixtureBackend("anchor")
  descriptor:=adapter.FakeIPRuntimeNamespaceDescriptor{Version:1,AnchorDatabaseID:"anchor",Backend:anchor.descriptor,ID:"one",LogicalID:"one",EffectiveConfigurationID:"selected"}
  if !mixed { descriptor.Version=2 }
  link:=adapter.FakeIPRuntimeLink{ID:"ready",EffectiveConfigurationID:"selected",DiscoveryReady:true,Namespaces:[]adapter.FakeIPRuntimeNamespaceDescriptor{descriptor}}
  if mixed { foreign:=descriptor; foreign.ID="other"; foreign.AnchorDatabaseID="other-root"; link.Namespaces=append(link.Namespaces,foreign) }
  anchor.links[link.ID]=link
  m:=fixtureEmptyManager(t)
  if err:=m.RecoverPersistent(context.Background(),anchor,fixtureResolver(anchor),"selected"); !errors.Is(err,ErrPersistenceIdentity) { t.Fatal("unknown ownership accepted",err) }
  if anchor.reclaims!=0||anchor.linkRemovals!=0||len(anchor.links)!=1||len(anchor.deadlines)!=0 { t.Fatal("invalid format changed stored data") }
 }) }
}

func TestRetiredAuthorityOutranksDelayedOldObserveAfterRestart(t *testing.T) {
 anchor:=fixtureBackend("anchor"); prefix:=netip.MustParsePrefix("198.18.0.0/29"); address:=prefix.Addr().Next().Next()
 descriptor:=adapter.FakeIPRuntimeNamespaceDescriptor{Version:1,AnchorDatabaseID:"anchor",Backend:anchor.descriptor,ID:"old-live",LogicalID:"old-live",EffectiveConfigurationID:"selected"}
 handle,err:=anchor.PrepareFakeIPNamespace(context.Background(),descriptor,adapter.FakeIPStorageSnapshot{Metadata:&adapter.FakeIPMetadata{Inet4Range:prefix},Mappings:map[netip.Addr]string{address:"old.example"}}); if err!=nil { t.Fatal(err) }
 anchor.links["old-link"]=adapter.FakeIPRuntimeLink{ID:"old-link",EffectiveConfigurationID:"selected",DiscoveryReady:true,Namespaces:[]adapter.FakeIPRuntimeNamespaceDescriptor{descriptor}}
 old:=adapter.FakeIPRuntimeAnswer{Token:1,Address:address,Domain:"old.example",Revision:10,PendingTTL:600}
 entered,release:=make(chan struct{}),make(chan struct{}); var releaseOnce sync.Once; t.Cleanup(func(){releaseOnce.Do(func(){close(release)})}); anchor.observeBarrier=func(){close(entered);<-release}
 observed:=make(chan error,1); go func(){observed<-handle.Observe(context.Background(),[]adapter.FakeIPRuntimeAnswer{old})}(); waitFixture(t,entered)
 newer:=adapter.FakeIPRuntimeAnswer{Address:address,Domain:"reused.example",Revision:20,Obsolete:true}
 if err=anchor.RetainFakeIPRuntimeAuthority(context.Background(),[]adapter.FakeIPRuntimeAnswer{newer}); err!=nil { t.Fatal(err) }
 live:=fixtureEmptyManager(t); live.counterRoot=anchor; live.persistenceResolver=fixtureResolver(anchor)
 // A still-linked old namespace keeps the authority even before Observe has
 // stored a certificate. Existing ownership, not a pending disk count, decides.
 if err=live.pruneRetainedAuthority(context.Background()); err!=nil { t.Fatal(err) }
 if len(anchor.authority)!=1 { t.Fatal("authority pruned ahead of actual old writer") }
 releaseOnce.Do(func(){close(release)}); if err=<-observed; err!=nil { t.Fatal(err) }
 restarted:=fixtureEmptyManager(t)
 if err=restarted.RecoverPersistent(context.Background(),anchor,fixtureResolver(anchor),"selected"); err!=nil { t.Fatal(err) }
 if _,found:=restarted.lookup(address); found { t.Fatal("delayed older pending certificate resurrected a reused identity") }
 delete(anchor.links,"old-link")
 if err=live.pruneRetainedAuthority(context.Background()); err!=nil { t.Fatal(err) }
 if len(anchor.authority)!=0 { t.Fatal("authority survived after the last containing namespace drained") }
}
