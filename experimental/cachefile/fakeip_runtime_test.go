package cachefile

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

// Pure fixtures only: no file, bbolt database, platform API or native worker is
// opened by these tests. Real filesystem fault tests remain joint native work.
func TestRuntimeSnapshotRejectsAmbiguousIdentityAndUnknownSchema(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.0/29"); address := netip.MustParseAddr("198.18.0.2")
	answer := adapter.FakeIPRuntimeAnswer{Address: address, Domain: "one.example", Revision: 4, Pending: 1, PendingTTL: 60}
	token := answer; token.Token = 9
	snapshot := adapter.FakeIPStorageSnapshot{Metadata: &adapter.FakeIPMetadata{Inet4Range: prefix}, Mappings: map[netip.Addr]string{address: answer.Domain}, Answers: []adapter.FakeIPRuntimeAnswer{answer}, PendingAnswers: []adapter.FakeIPRuntimeAnswer{token}}
	if err := validateRuntimeSnapshot(snapshot); err != nil { t.Fatal(err) }
	snapshot.PendingAnswers = append(snapshot.PendingAnswers, token)
	if err := validateRuntimeSnapshot(snapshot); !errors.Is(err, ErrFakeIPRuntimeConflict) { t.Fatal("duplicate exact token admitted", err) }
	snapshot.PendingAnswers = []adapter.FakeIPRuntimeAnswer{token}; snapshot.PendingAnswers[0].Revision++
	if err := validateRuntimeSnapshot(snapshot); !errors.Is(err, ErrFakeIPRuntimeConflict) { t.Fatal("token with another mapping revision admitted", err) }
	identity := []byte("00000000000000000000000000000001")
	if err := validateRuntimeHeader([]byte{1}, identity); err != nil { t.Fatal(err) }
	if err := validateRuntimeHeader([]byte{2}, identity); !errors.Is(err, ErrFakeIPRuntimeVersion) { t.Fatal("unknown schema silently reinterpreted", err) }
	if err := validateRuntimeHeader([]byte{1}, []byte("reused-path")); !errors.Is(err, ErrFakeIPRuntimeIdentity) { t.Fatal("malformed file identity admitted", err) }
}

func TestRuntimeAllocationMirrorAndPendingTokenBatchAreFinite(t *testing.T) {
	cache := &CacheFile{pending: newPendingWrites(), bufferSize: defaultBufferSize, flushSignal: make(chan struct{}, 1)}
	address := netip.MustParseAddr("198.18.0.2")
	n := newRuntimeNamespace(cache, adapter.FakeIPRuntimeNamespaceDescriptor{ID: "fixture"}, adapter.FakeIPStorageSnapshot{Metadata: &adapter.FakeIPMetadata{Inet4Range: netip.MustParsePrefix("198.18.0.0/29")}, Mappings: map[netip.Addr]string{address: "old.example"}})
	// DB is nil: ordinary namespace lookup/queue must be wholly RAM-only.
	n.FakeIPStoreAsync(address, "new.example", nil)
	if _, found := n.FakeIPLoadDomain("old.example", false); found { t.Fatal("old forward mapping survived reuse") }
	if domain, found := n.FakeIPLoad(address); !found || domain != "new.example" { t.Fatal("new allocation missing") }
	image := n.SnapshotAllocation(); image.Mappings[address] = "mutated.example"
	if domain, _ := n.FakeIPLoad(address); domain != "new.example" { t.Fatal("snapshot aliases allocation mirror") }
	token := adapter.FakeIPRuntimeAnswer{Token: 7, Address: address, Domain: "new.example", Revision: 2, Pending: 1, PendingTTL: 60}
	n.queueAnswerLocked(token, true); n.queueTokenLocked(token, false)
	before := cache.pending.count
	at := time.Unix(100, 0)
	if err := n.Complete(context.Background(), []adapter.FakeIPRuntimeAnswer{token}, at, true); err != nil { t.Fatal(err) }
	if err := n.Complete(context.Background(), []adapter.FakeIPRuntimeAnswer{token}, at.Add(time.Hour), true); err != nil { t.Fatal(err) }
	current := cache.pending.fakeIPRuntime["fixture"].answers[address]
	if current.Pending != 0 || !current.ExpiresAt.Equal(at.Add(time.Minute)) { t.Fatal("duplicate completion changed pending/absolute expiry", current) }
	if cache.pending.count != before || cache.pending.size < len(runtimeTokenKey(token))+64 { t.Fatal("token bookkeeping escaped configured batch byte accounting") }
	failed := cache.pending; cache.pending = newPendingWrites(); cache.restoreFakeIPLocked(failed)
	if _, present := cache.pending.fakeIPRuntime["fixture"].tokens[string(runtimeTokenKey(token))]; !present { t.Fatal("failed batch lost exact completion tombstone") }
	cache.dropRuntimePendingLocked("fixture")
	if cache.pending.count != 0 || cache.pending.size != 0 { t.Fatal("reclaimed namespace retained pending accounting", cache.pending.count, cache.pending.size) }
}

type fixtureResourceLease struct { releases *atomic.Int32 }
func (l *fixtureResourceLease) ID() adapter.RuntimeResourceID { return adapter.RuntimeResourceID{Incarnation: "fixture", Sequence: 1} }
func (l *fixtureResourceLease) Fork() (adapter.RuntimeResourceLease, error) { return &fixtureResourceLease{releases: l.releases}, nil }
func (l *fixtureResourceLease) Retiring() <-chan struct{} { return nil }
func (l *fixtureResourceLease) Release() { l.releases.Add(1) }
type fixtureBoundBackend struct { adapter.FakeIPRuntimeBackend }

func TestBackendBusySealWaitCancellationAndActualUnbind(t *testing.T) {
	d := adapter.FakeIPRuntimeBackendDescriptor{Path: "/fixture/cache", DatabaseID: "database"}
	backend := &fixtureBoundBackend{}
	entry := &recoveryBackend{backend: backend, bindings: 1, changed: make(chan struct{})}
	journal := &FakeIPRuntimeJournal{backends: map[adapter.FakeIPRuntimeBackendDescriptor]*recoveryBackend{d: entry}}
	var released atomic.Int32
	binding := &FakeIPBackendBinding{journal: journal, descriptor: d, entry: entry, owner: &fixtureResourceLease{releases: &released}}
	borrowed, release, err := journal.ResolveFakeIPRuntime(context.Background(), d); if err != nil || borrowed != backend { t.Fatal(err) }
	if err = binding.Unbind(context.Background()); !errors.Is(err, ErrFakeIPRecoveryBusy) { t.Fatal("live namespace owner did not hold retirement", err) }
	if _, _, err = journal.ResolveFakeIPRuntime(context.Background(), d); !errors.Is(err, ErrFakeIPRecoveryBusy) { t.Fatal("sealed final binding admitted new borrow", err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if err = binding.WaitIdle(ctx); !errors.Is(err, context.Canceled) || released.Load() != 0 { t.Fatal("canceled wait released physical backend", err) }
	// Existing borrowed remains usable: no method on its private handle asks
	// this now-sealed registry to authorize an already admitted operation.
	if borrowed != backend { t.Fatal("retirement replaced admitted backend identity") }
	if err = release(); err != nil { t.Fatal(err) }
	if err = binding.WaitIdle(context.Background()); err != nil { t.Fatal(err) }
	if err = binding.Unbind(context.Background()); err != nil { t.Fatal(err) }
	if err = binding.Unbind(context.Background()); err != nil || released.Load() != 1 { t.Fatal("unbind was not exactly once", err, released.Load()) }
}

func TestStrictOpenAndPromotedHandleNeverEnterLegacyReset(t *testing.T) {
 expected := adapter.FakeIPRuntimeBackendDescriptor{Path: "/fixture/owned", CacheID: "selected", DatabaseID: "immutable"}
 ctx := ContextWithFakeIPRuntimeOpen(context.Background(), &expected)
 expected.DatabaseID = "caller-mutated"
 request, found := fakeIPRuntimeOpenFromContext(ctx)
 if !found || request.expected.DatabaseID != "immutable" { t.Fatal("strict-open descriptor aliases caller memory") }
 if err := validateRuntimeOpenIdentity("/fixture/other", "selected", request); !errors.Is(err, ErrFakeIPRuntimeIdentity) { t.Fatal("wrong configured path accepted", err) }
 if _, found := fakeIPRuntimeOpenFromContext(context.Background()); found { t.Fatal("unrelated legacy cache was silently promoted") }
 cache := &CacheFile{ctx: ctx, logger: log.NewNOPFactory().Logger()}
 cache.runtimeStrict.Store(true)
 // A nil database would panic in the destructive legacy branch. This guard
 // must return without a filesystem operation, close, deletion or replacement.
 cache.resetDB(nil, "injected corruption")
 if cache.DB != nil || !cache.runtimeStrict.Load() { t.Fatal("strict promotion was reversed by corruption") }
}

func TestCacheIDViewsShareOnePhysicalOwnerAndDrainAliases(t *testing.T) {
 physical := &CacheFile{cacheIDText: "physical-original", cacheID: []byte("physical-original")}
 oldDescriptor := adapter.FakeIPRuntimeBackendDescriptor{Path:"/fixture/shared", DatabaseID:"physical", CacheID:"old"}; nextDescriptor := oldDescriptor; nextDescriptor.CacheID = "new"
 oldView := &fakeIPRuntimeBackendView{physical: physical, descriptor: oldDescriptor}; nextView := &fakeIPRuntimeBackendView{physical: physical, descriptor: nextDescriptor}
 if !samePhysicalRuntimeBackend(oldView, nextView) || physical.cacheIDText != "physical-original" { t.Fatal("logical view mutated or reopened physical cache") }
 if _, hasClose := any(oldView).(interface{ Close() error }); hasClose { t.Fatal("view can independently close the shared DB") }
 oldNamespace := adapter.FakeIPRuntimeNamespaceDescriptor{Version:1,AnchorDatabaseID:"owner",Backend:oldDescriptor, ID:"old",LogicalID:"old",EffectiveConfigurationID:"old"}; nextNamespace := adapter.FakeIPRuntimeNamespaceDescriptor{Version:1,AnchorDatabaseID:"owner",Backend:nextDescriptor, ID:"new",LogicalID:"new",EffectiveConfigurationID:"new"}
 filtered := filterRuntimeCatalog(nextDescriptor, adapter.FakeIPRuntimeCatalog{Namespaces:[]adapter.FakeIPRuntimeNamespaceDescriptor{oldNamespace,nextNamespace}, Links:[]adapter.FakeIPRuntimeLink{{ID:"old-only",Namespaces:[]adapter.FakeIPRuntimeNamespaceDescriptor{oldNamespace}},{ID:"both",Namespaces:[]adapter.FakeIPRuntimeNamespaceDescriptor{oldNamespace,nextNamespace}}}})
 if len(filtered.Namespaces)!=1 || filtered.Namespaces[0].ID!="new" || len(filtered.Links)!=1 || filtered.Links[0].ID!="both" { t.Fatal("cache-ID namespace/catalog isolation failed") }
 if _, err := physical.prepareFakeIPNamespace(context.Background(), nextDescriptor, oldNamespace, adapter.FakeIPStorageSnapshot{}); !errors.Is(err, ErrFakeIPRuntimeIdentity) { t.Fatal("new view admitted old descriptor",err) }
 journal := &FakeIPRuntimeJournal{backends:make(map[adapter.FakeIPRuntimeBackendDescriptor]*recoveryBackend)}
 entry := &recoveryBackend{backend:physical,changed:make(chan struct{})}; old := journal.addViewLocked(entry,oldDescriptor,oldView); next := journal.addViewLocked(entry,nextDescriptor,nextView)
 entry.bindings=2; old.bindings=1; next.bindings=1
 var released atomic.Int32
 oldBinding := &FakeIPBackendBinding{journal:journal,descriptor:oldDescriptor,entry:entry,view:old,owner:&fixtureResourceLease{releases:&released}}
 nextBinding := &FakeIPBackendBinding{journal:journal,descriptor:nextDescriptor,entry:entry,view:next,owner:&fixtureResourceLease{releases:&released}}
 first, releaseOld, err := journal.ResolveFakeIPRuntime(context.Background(),oldDescriptor); if err!=nil || first!=oldView { t.Fatal(err) }
 second, releaseNew, err := journal.ResolveFakeIPRuntime(context.Background(),nextDescriptor); if err!=nil || second!=nextView { t.Fatal(err) }
 if err=oldBinding.Unbind(context.Background()); err!=nil || released.Load()!=1 { t.Fatal("replacement binding did not preserve shared physical ownership",err) }
 if entry.retiring { t.Fatal("non-final binding sealed replacement admission") }
 if err=releaseOld(); err!=nil { t.Fatal(err) }; if journal.backends[oldDescriptor]!=nil { t.Fatal("drained old logical alias retained forever") }
 if err=nextBinding.Unbind(context.Background()); !errors.Is(err,ErrFakeIPRecoveryBusy) { t.Fatal(err) }
 if err=releaseNew(); err!=nil { t.Fatal(err) }; if err=nextBinding.Unbind(context.Background()); err!=nil || released.Load()!=2 { t.Fatal(err) }
 if len(journal.backends)!=0 { t.Fatal("final unbind left a stale writer alias") }
 journal.addViewLocked(entry,nextDescriptor,nextView)
 alias := nextDescriptor; alias.Path="/fixture/alias"; if _,err=journal.physicalBackendLocked(alias); !errors.Is(err,ErrFakeIPRuntimeIdentity) { t.Fatal("same database under another path was accepted",err) }
 replacement := nextDescriptor; replacement.DatabaseID="replacement"; if _,err=journal.physicalBackendLocked(replacement); !errors.Is(err,ErrFakeIPRuntimeIdentity) { t.Fatal("path replacement reused physical owner",err) }
}

func TestAuthorityBatchRejectsStaleAnswerAndHasOneTombstonePerAddress(t *testing.T) {
 address := netip.MustParseAddr("198.18.0.2")
 latest := adapter.FakeIPRuntimeAnswer{Address:address,Domain:"new.example",Revision:20,Obsolete:true}
 older := adapter.FakeIPRuntimeAnswer{Address:address,Domain:"old.example",Revision:19,Pending:1,PendingTTL:600}
 if write, err := mergeRuntimeAnswer(latest,true,older); err!=nil || write { t.Fatal("old pending certificate overwrote newer authority",err) }
 conflict := older; conflict.Revision=latest.Revision
 if _,err := mergeRuntimeAnswer(latest,true,conflict); !errors.Is(err,ErrFakeIPRuntimeConflict) { t.Fatal("equal revision changed domain",err) }
 admitted := latest; admitted.Obsolete=false; admitted.Pending=1
 if write,err := mergeRuntimeAnswer(latest,true,admitted); err!=nil || !write { t.Fatal("actual answer could not replace same-identity allocation marker",err) }
 latest.Superseded=true
 if write,err := mergeRuntimeAnswer(latest,true,admitted); err!=nil || write { t.Fatal("exact invalidation was resurrected",err) }
 cache := &CacheFile{pending:newPendingWrites(),bufferSize:defaultBufferSize,flushSignal:make(chan struct{},1)}
 namespace := newRuntimeNamespace(cache,adapter.FakeIPRuntimeNamespaceDescriptor{ID:"bounded"},adapter.FakeIPStorageSnapshot{})
 for revision:=uint64(1); revision<=10000; revision++ { latest.Revision=revision; namespace.QueueAuthority(latest) }
 pending := cache.pending.fakeIPRuntime["bounded"]
 if len(pending.authorities)!=1 || cache.pending.count!=1 || cache.pending.size!=len(latest.Domain)+64 { t.Fatal("authority records grew with reuse history") }
 cache.dropRuntimePendingLocked("bounded"); if cache.pending.count!=0 || cache.pending.size!=0 { t.Fatal("authority bookkeeping survived namespace reclamation") }
}

func TestOrphanSelectionRequiresKnownFormatAndExactAnchorOwnership(t *testing.T) {
 backend:=adapter.FakeIPRuntimeBackendDescriptor{Path:"/fixture/cache",DatabaseID:"physical",CacheID:"old"}
 kept:=adapter.FakeIPRuntimeNamespaceDescriptor{Version:1,AnchorDatabaseID:"owner",Backend:backend,ID:"kept",LogicalID:"kept",EffectiveConfigurationID:"selected"}
 orphan:=kept; orphan.ID="old-cache-orphan"
 foreign:=orphan; foreign.ID="foreign"; foreign.AnchorDatabaseID="other-owner"
 nextCache:=kept; nextCache.ID="next-cache"; nextCache.Backend.CacheID="next"
 removed,err:=runtimeOrphanIDs("owner",[]adapter.FakeIPRuntimeNamespaceDescriptor{kept,orphan,foreign,nextCache},[]adapter.FakeIPRuntimeNamespaceDescriptor{kept,nextCache})
 if err!=nil||len(removed)!=1||removed[0]!=orphan.ID { t.Fatal("anchor/cache-ID ownership mismatch",removed,err) }
 unknown:=orphan; unknown.Version=2
 for _,catalog:=range [][]adapter.FakeIPRuntimeNamespaceDescriptor{{orphan,unknown},{orphan,{}}} {
  if selected,err:=runtimeOrphanIDs("owner",catalog,nil); err==nil||selected!=nil { t.Fatal("invalid later descriptor leaked a partial delete plan") }
 }
 if selected,err:=runtimeOrphanIDs("",[]adapter.FakeIPRuntimeNamespaceDescriptor{orphan},nil); err==nil||selected!=nil { t.Fatal("absent anchor authorized cleanup") }
 if selected,err:=runtimeOrphanIDs("owner",[]adapter.FakeIPRuntimeNamespaceDescriptor{orphan},[]adapter.FakeIPRuntimeNamespaceDescriptor{foreign}); err==nil||selected!=nil { t.Fatal("foreign allowlist authorized cleanup") }
}

func TestRetainedAuthorityMergeAndUnknownOwnershipFailClosed(t *testing.T) {
 address:=netip.MustParseAddr("198.18.0.2"); latest:=adapter.FakeIPRuntimeAnswer{Address:address,Domain:"new.example",Revision:20,Obsolete:true}
 old:=latest; old.Revision=10; old.Domain="old.example"
 merged,err:=mergeRetainedAuthority(latest,old); if err!=nil||merged.Revision!=20||merged.Domain!="new.example" { t.Fatal("lower revision replaced retained authority",err) }
 old.Revision=20; if _,err=mergeRetainedAuthority(latest,old); !errors.Is(err,ErrFakeIPRuntimeConflict) { t.Fatal("equal revision domain conflict accepted",err) }
 for _,raw:=range []string{`{"Version":2,"AnchorDatabaseID":"owner"}`,`{"Version":1,"AnchorDatabaseID":"foreign"}`} { if _,err=decodeRuntimeAuthority([]byte(raw),"owner"); err==nil { t.Fatal("foreign/future authority was accepted") } }
}
