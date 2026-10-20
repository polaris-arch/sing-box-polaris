package cachefile

import (
 "context"
 "net/netip"
 "time"

 "github.com/sagernet/sing-box/adapter"
)

// A logical fake-IP backend view never mutates CacheFile.cacheID and never
// independently closes the shared DB. Its journal binding and resolver borrows
// retain the actual physical owner. It is not a general DNS/RDRC cache view.
type fakeIPRuntimeBackendView struct {
 physical *CacheFile
 descriptor adapter.FakeIPRuntimeBackendDescriptor
}
func (v *fakeIPRuntimeBackendView) RuntimeDescriptor(ctx context.Context) (adapter.FakeIPRuntimeBackendDescriptor, error) {
 actual, err := v.physical.RuntimeDescriptor(ctx); if err != nil { return v.descriptor, err }
 if actual.Path != v.descriptor.Path || actual.DatabaseID != v.descriptor.DatabaseID { return v.descriptor, ErrFakeIPRuntimeIdentity }
 return v.descriptor, nil
}
func (v *fakeIPRuntimeBackendView) PrepareFakeIPNamespace(ctx context.Context, descriptor adapter.FakeIPRuntimeNamespaceDescriptor, image adapter.FakeIPStorageSnapshot) (adapter.FakeIPRuntimeNamespace, error) {
 actual, err := v.RuntimeDescriptor(ctx); if err != nil { return nil, err }; return v.physical.prepareFakeIPNamespace(ctx, actual, descriptor, image)
}
func (v *fakeIPRuntimeBackendView) OpenFakeIPNamespace(ctx context.Context, id string) (adapter.FakeIPRuntimeNamespace, error) {
 actual, err := v.RuntimeDescriptor(ctx); if err != nil { return nil, err }; return v.physical.openFakeIPNamespace(ctx, actual, id)
}
func (v *fakeIPRuntimeBackendView) FakeIPRuntimeCatalog(ctx context.Context) (adapter.FakeIPRuntimeCatalog, error) {
 actual, err := v.RuntimeDescriptor(ctx); if err != nil { return adapter.FakeIPRuntimeCatalog{}, err }; return v.physical.fakeIPRuntimeCatalog(ctx, actual)
}
func (v *fakeIPRuntimeBackendView) SaveFakeIPRuntimeLink(ctx context.Context, link adapter.FakeIPRuntimeLink) error {
 actual, err := v.RuntimeDescriptor(ctx); if err != nil { return err }; return v.physical.saveFakeIPRuntimeLink(ctx, actual, link)
}
func physicalRuntimeCache(backend adapter.FakeIPRuntimeBackend) *CacheFile {
 switch value := backend.(type) { case *CacheFile: return value; case *fakeIPRuntimeBackendView: return value.physical; case *FakeIPRuntimeJournal: return value.CacheFile; default: return nil }
}

// BindBackendCacheIDOwned adds one logical namespace view of an already open
// physical cache, avoiding a second bbolt writer for cache_id-only changes.
// Retain the returned binding and follow its Unbind/WaitIdle lifecycle. The
// view is valid only under this binding or an admitted resolver continuation.
func (j *FakeIPRuntimeJournal) BindBackendCacheIDOwned(ctx context.Context, physical *CacheFile, cacheID string, borrowed adapter.RuntimeResourceLease) (adapter.FakeIPRuntimeBackend, *FakeIPBackendBinding, error) {
 var held adapter.RuntimeResourceLease
 if borrowed != nil { var err error; held, err = borrowed.Fork(); if err != nil { return nil, nil, err }; defer held.Release() }
 descriptor, err := physical.RuntimeDescriptor(ctx); if err != nil { return nil, nil, err }; descriptor.CacheID = cacheID
 view := &fakeIPRuntimeBackendView{physical: physical, descriptor: descriptor}
 binding, err := j.BindBackendOwned(ctx, view, held); if err != nil { return nil, nil, err }
 return view, binding, nil
}
var _ adapter.FakeIPRuntimeBackend = (*fakeIPRuntimeBackendView)(nil)

func (v *fakeIPRuntimeBackendView) ReserveFakeIPRuntimeCounters(ctx context.Context, minimum adapter.FakeIPRuntimeCounters, count uint64) (adapter.FakeIPRuntimeCounters, adapter.FakeIPRuntimeCounters, error) { return v.physical.ReserveFakeIPRuntimeCounters(ctx, minimum, count) }
func (v *fakeIPRuntimeBackendView) AllocateFakeIPGeneration(ctx context.Context) (uint64, error) { return v.physical.AllocateFakeIPGeneration(ctx) }
func (v *fakeIPRuntimeBackendView) SnapshotFakeIP(ctx context.Context) (adapter.FakeIPStorageSnapshot, error) { return v.physical.SnapshotFakeIP(ctx) }
func (v *fakeIPRuntimeBackendView) RemoveFakeIPRuntimeLink(ctx context.Context, id string) error { return v.physical.RemoveFakeIPRuntimeLink(ctx, id) }
func (v *fakeIPRuntimeBackendView) ResolveFakeIPPendingExpiries(ctx context.Context, tokens []adapter.FakeIPRuntimeAnswer, now time.Time) (map[uint64]time.Time, uint64, error) { return v.physical.ResolveFakeIPPendingExpiries(ctx, tokens, now) }
func (v *fakeIPRuntimeBackendView) ReleaseFakeIPPendingExpiries(ctx context.Context, tokens []uint64) error { return v.physical.ReleaseFakeIPPendingExpiries(ctx, tokens) }

func (v *fakeIPRuntimeBackendView) ReclaimFakeIPRuntimeOrphans(ctx context.Context, anchorID string, allowed []adapter.FakeIPRuntimeNamespaceDescriptor) error { return v.physical.ReclaimFakeIPRuntimeOrphans(ctx, anchorID, allowed) }

func (v *fakeIPRuntimeBackendView) RetainFakeIPRuntimeAuthority(ctx context.Context, records []adapter.FakeIPRuntimeAnswer) error { return v.physical.RetainFakeIPRuntimeAuthority(ctx,records) }
func (v *fakeIPRuntimeBackendView) FakeIPRuntimeAuthority(ctx context.Context) ([]adapter.FakeIPRuntimeAnswer,error) { return v.physical.FakeIPRuntimeAuthority(ctx) }
func (v *fakeIPRuntimeBackendView) PruneFakeIPRuntimeAuthority(ctx context.Context, ranges []netip.Prefix) error { return v.physical.PruneFakeIPRuntimeAuthority(ctx,ranges) }
