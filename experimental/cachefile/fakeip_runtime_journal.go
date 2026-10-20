package cachefile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

var (
	ErrFakeIPRecoveryRoot = errors.New("fake-IP recovery requires a declared private absolute host root")
	ErrFakeIPRecoveryCustody = errors.New("fake-IP recovery path lacks verified custody")
	ErrFakeIPRecoveryBusy = errors.New("fake-IP backend still has namespace or transition owners")
	ErrFakeIPRecoveryClosed = errors.New("fake-IP recovery journal is closed")
	bucketRuntimeCustody = []byte("custody")
)
const fakeIPRuntimeJournalName = "sing-box-hot-fakeip-v1.db"

type recoveryBackendView struct { backend adapter.FakeIPRuntimeBackend; references uint64; bindings uint64 }
type recoveryBackend struct {
	views map[adapter.FakeIPRuntimeBackendDescriptor]*recoveryBackendView
	permanent bool
	backend adapter.FakeIPRuntimeBackend
	owned *CacheFile
	references uint64
	bindings uint64
	failure error
	retiring bool
	changed chan struct{}
}

// FakeIPRuntimeJournal is independent of cache.db's resettable lifecycle. It
// records custody, not configuration selection, and is retained for Box lifetime.
// A successful open proves only the filesystem's reported sync contract; it does
// not claim hardware power-loss guarantees beyond the OS/filesystem contract.
type FakeIPRuntimeJournal struct {
	*CacheFile
	access sync.Mutex
	maintenance sync.Mutex // slow custody changes, never an answer admission lock
	closed bool
	backends map[adapter.FakeIPRuntimeBackendDescriptor]*recoveryBackend
	cancel context.CancelFunc
	flushDone chan struct{}
	closeErr error
}

func OpenFakeIPRuntimeJournal(ctx context.Context, log logger.Logger) (*FakeIPRuntimeJournal, error) {
	root, present := adapter.RuntimeRecoveryRootFromContext(ctx)
	if !present || !filepath.IsAbs(root) { return nil, ErrFakeIPRecoveryRoot }
	root = filepath.Clean(root)
	rootInfo, err := os.Lstat(root)
	if err != nil { return nil, fmt.Errorf("%w: %v", ErrFakeIPRecoveryCustody, err) }
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o022 != 0 { return nil, ErrFakeIPRecoveryCustody }
	canonical, err := filepath.EvalSymlinks(root); if err != nil { return nil, err }
	path := filepath.Join(canonical, fakeIPRuntimeJournalName)
	created := false
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil { created = true } else if errors.Is(err, os.ErrExist) {
		info, inspectErr := os.Lstat(path)
		if inspectErr != nil { return nil, inspectErr }
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 { return nil, ErrFakeIPRecoveryCustody }
		file, err = os.OpenFile(path, os.O_RDWR, 0)
	}
	if err != nil { return nil, err }
	opened, err := file.Stat()
	if err == nil { err = file.Sync() }
	closeErr := file.Close(); if err == nil { err = closeErr }
	if err != nil { return nil, err }
	if !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 { return nil, ErrFakeIPRecoveryCustody }
	if created {
		if err = syncRuntimeFileCreation(path); err != nil { return nil, fmt.Errorf("fake-IP recovery creation durability unsupported: %w", err) }
	}
	cache, err := openStrictRuntimeCache(ctx, log, path, "", opened)
	if err != nil { return nil, err }
	currentRoot, err := os.Stat(root)
	if err != nil || !os.SameFile(rootInfo, currentRoot) { _ = closeStrictRuntimeCache(cache); return nil, ErrFakeIPRecoveryCustody }
	if _, err = cache.RuntimeDescriptor(ctx); err != nil { _ = closeStrictRuntimeCache(cache); return nil, err }
	if err = cache.runtimeUpdate(func(tx *bbolt.Tx) error { root, err := runtimeRoot(tx); if err != nil { return err }; _, err = root.CreateBucketIfNotExists(bucketRuntimeCustody); return err }); err != nil { _ = closeStrictRuntimeCache(cache); return nil, err }
	flushCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	journal := &FakeIPRuntimeJournal{CacheFile: cache, backends: make(map[adapter.FakeIPRuntimeBackendDescriptor]*recoveryBackend), cancel: cancel, flushDone: make(chan struct{})}
	descriptor, _ := cache.RuntimeDescriptor(ctx)
	entry := &recoveryBackend{backend: cache, permanent: true, changed: make(chan struct{})}
	journal.addViewLocked(entry, descriptor, cache)
	go func() { defer close(journal.flushDone); cache.loopFlush(flushCtx) }()
	return journal, nil
}

func openStrictRuntimeDatabase(ctx context.Context, path string, expected os.FileInfo) (*bbolt.DB, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	if !filepath.IsAbs(path) { return nil, ErrFakeIPRecoveryCustody }
	before, err := os.Lstat(path); if err != nil { return nil, err }
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || (expected != nil && !os.SameFile(before, expected)) { return nil, ErrFakeIPRecoveryCustody }
	opts := databaseOptions
	// bbolt's exclusive writer lock bounds competing live opens. No retry,
	// auto-reset, file deletion, chmod or bucket cleanup is permitted here.
	opts.Timeout = time.Second
	db, err := bbolt.Open(path, 0o600, &opts); if err != nil { return nil, err }
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode()&os.ModeSymlink != 0 { _ = db.Close(); return nil, ErrFakeIPRecoveryCustody }
	if err = checkDatabase(db); err != nil { _ = db.Close(); return nil, err }
	return db, nil
}
func openStrictRuntimeCache(ctx context.Context, log logger.Logger, path, cacheID string, expected os.FileInfo) (*CacheFile, error) {
	if expected == nil { var err error; expected, err = os.Lstat(path); if err != nil { return nil, err } }
	db, err := openStrictRuntimeDatabase(ctx, path, expected); if err != nil { return nil, err }
	cache := New(ctx, log, option.CacheFileOptions{Path: path, CacheID: cacheID})
	cache.DB = db; cache.runtimeStrict.Store(true)
	cache.runtimeFileInfo, err = os.Lstat(path)
	if err != nil { _ = db.Close(); return nil, err }
	if expected != nil && !os.SameFile(expected, cache.runtimeFileInfo) { _ = db.Close(); return nil, ErrFakeIPRuntimeIdentity }
	return cache, nil
}
func closeStrictRuntimeCache(cache *CacheFile) error {
	if err := cache.FlushFakeIP(context.Background()); err != nil { return fmt.Errorf("fake-IP backend retained after failed flush: %v", err) }
	cache.dbAccess.Lock(); defer cache.dbAccess.Unlock()
	if cache.DB == nil { return nil }
	err := cache.DB.Close(); if err == nil { cache.DB = nil }
	return err
}

// BindBackend is for an explicitly Box-owned backend whose owner independently
// outlives this journal. Retain and Unbind its returned handle before Close.
// Graph-managed cache resources must use BindBackendOwned.
func (j *FakeIPRuntimeJournal) BindBackend(ctx context.Context, backend adapter.FakeIPRuntimeBackend) (*FakeIPBackendBinding, error) {
	return j.BindBackendOwned(ctx, backend, nil)
}

// BindBackendOwned forks the physical resource before any backend access. The
// returned unbind is retryable while resolver references remain; it never waits
// for cleanup that itself needs cache retirement. Call it BEFORE releasing the
// coordinator's cache ownership. Durable custody remains until ForgetBackend.
func (j *FakeIPRuntimeJournal) BindBackendOwned(ctx context.Context, backend adapter.FakeIPRuntimeBackend, borrowed adapter.RuntimeResourceLease) (*FakeIPBackendBinding, error) {
	var owner adapter.RuntimeResourceLease
	var err error
	if borrowed != nil { owner, err = borrowed.Fork(); if err != nil { return nil, err } }
	retained := false
	defer func() { if !retained && owner != nil { owner.Release() } }()
	descriptor, err := backend.RuntimeDescriptor(ctx); if err != nil { return nil, err }
	if !filepath.IsAbs(descriptor.Path) || descriptor.DatabaseID == "" { return nil, ErrFakeIPRecoveryCustody }
	info, inspectErr := os.Lstat(descriptor.Path); if inspectErr != nil { return nil, inspectErr }; if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 { return nil, ErrFakeIPRecoveryCustody }
	j.maintenance.Lock(); defer j.maintenance.Unlock()
	j.access.Lock()
	if j.closed { j.access.Unlock(); return nil, ErrFakeIPRecoveryClosed }
	entry, identityErr := j.physicalBackendLocked(descriptor)
	if identityErr != nil { j.access.Unlock(); return nil, identityErr }
	if entry != nil && (entry.owned != nil || entry.failure != nil || entry.retiring || !samePhysicalRuntimeBackend(entry.backend, backend)) { j.access.Unlock(); return nil, ErrFakeIPRuntimeConflict }
	j.access.Unlock()
	if err = ctx.Err(); err != nil { return nil, err }
	err = j.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }
		custody := root.Bucket(bucketRuntimeCustody)
		key := []byte(descriptor.DatabaseID + "\x00" + descriptor.CacheID)
		if raw := custody.Get(key); len(raw) != 0 { var old adapter.FakeIPRuntimeBackendDescriptor; if err := json.Unmarshal(raw, &old); err != nil { return err }; if old != descriptor { return ErrFakeIPRuntimeIdentity } }
		return putRuntimeJSON(custody, key, descriptor)
	})
	if err != nil { return nil, err }
	j.access.Lock()
	if entry == nil { entry = &recoveryBackend{backend: backend, changed: make(chan struct{})} }
	view := j.addViewLocked(entry, descriptor, backend)
	entry.bindings++; view.bindings++
	j.access.Unlock()
	retained = true
	return &FakeIPBackendBinding{journal: j, descriptor: descriptor, entry: entry, view: view, owner: owner}, nil
}

// FakeIPBackendBinding is retained by the coordinator across a busy Unbind.
// WaitIdle observes actual namespace-reference drain; cancellation changes no
// ownership and never authorizes releasing the physical resource reservation.
type FakeIPBackendBinding struct {
	journal *FakeIPRuntimeJournal
	descriptor adapter.FakeIPRuntimeBackendDescriptor
	entry *recoveryBackend
	view *recoveryBackendView
	owner adapter.RuntimeResourceLease
	access sync.Mutex
	unbound bool
}
func (b *FakeIPBackendBinding) Unbind(ctx context.Context) error {
 b.access.Lock(); defer b.access.Unlock()
 if b.unbound { return nil }; if err := ctx.Err(); err != nil { return err }
 j := b.journal
 j.maintenance.Lock(); j.access.Lock()
 if b.entry.bindings == 1 {
  b.entry.retiring = true
  if b.entry.references != 0 { j.access.Unlock(); j.maintenance.Unlock(); return ErrFakeIPRecoveryBusy }
 }
 view := b.view; if view == nil { view = j.addViewLocked(b.entry, b.descriptor, b.entry.backend) }
 b.entry.bindings--; view.bindings--
 if b.entry.bindings == 0 { j.removeEntryLocked(b.entry) } else { j.removeUnusedViewLocked(b.entry, b.descriptor, view) }
 j.access.Unlock(); j.maintenance.Unlock()
 b.unbound = true
 if b.owner != nil { b.owner.Release() }
 return nil
}
func (b *FakeIPBackendBinding) WaitIdle(ctx context.Context) error {
	for {
		b.journal.access.Lock()
		if b.entry.references == 0 { b.journal.access.Unlock(); return nil }
		changed := b.entry.changed
		b.journal.access.Unlock()
		select { case <-changed: case <-ctx.Done(): return ctx.Err() }
	}
}

// ForgetBackend follows successful namespace/link reclamation and Unbind. A
// caller may not forget an old path merely because the new config is durable.
func (j *FakeIPRuntimeJournal) ForgetBackend(ctx context.Context, descriptor adapter.FakeIPRuntimeBackendDescriptor) error {
	j.maintenance.Lock(); defer j.maintenance.Unlock()
	j.access.Lock(); busy := j.backends[descriptor] != nil; closed := j.closed; j.access.Unlock()
	if closed { return ErrFakeIPRecoveryClosed }; if busy { return ErrFakeIPRecoveryBusy }
	if err := ctx.Err(); err != nil { return err }
	return j.runtimeUpdate(func(tx *bbolt.Tx) error {
		root, err := runtimeRoot(tx); if err != nil { return err }
		links := root.Bucket(bucketRuntimeLinks)
		if err = links.ForEach(func(_, raw []byte) error { var link adapter.FakeIPRuntimeLink; if err := json.Unmarshal(raw, &link); err != nil { return err }; for _, namespace := range link.Namespaces { if namespace.Backend == descriptor { return ErrFakeIPRecoveryBusy } }; return nil }); err != nil { return err }
		return root.Bucket(bucketRuntimeCustody).Delete([]byte(descriptor.DatabaseID+"\x00"+descriptor.CacheID))
	})
}

func samePhysicalRuntimeBackend(a, b adapter.FakeIPRuntimeBackend) bool {
 if a == b { return true }; physical := physicalRuntimeCache(a); return physical != nil && physical == physicalRuntimeCache(b)
}
// Called under access. File identity, not logical CacheID, selects the actual
// writer owner. A path alias or a replacement identity is an explicit conflict.
func (j *FakeIPRuntimeJournal) physicalBackendLocked(descriptor adapter.FakeIPRuntimeBackendDescriptor) (*recoveryBackend, error) {
 for known, entry := range j.backends {
  if known.Path == descriptor.Path || known.DatabaseID == descriptor.DatabaseID {
   if known.Path != descriptor.Path || known.DatabaseID != descriptor.DatabaseID { return nil, ErrFakeIPRuntimeIdentity }
   return entry, nil
  }
 }
 return nil, nil
}
func (j *FakeIPRuntimeJournal) addViewLocked(entry *recoveryBackend, descriptor adapter.FakeIPRuntimeBackendDescriptor, backend adapter.FakeIPRuntimeBackend) *recoveryBackendView {
 if entry.views == nil {
  entry.views = make(map[adapter.FakeIPRuntimeBackendDescriptor]*recoveryBackendView)
  // A manually supplied Box-owned entry may already have one binding.
  entry.views[descriptor] = &recoveryBackendView{backend: backend, bindings: entry.bindings}
 }
 view := entry.views[descriptor]
 if view == nil { view = &recoveryBackendView{backend: backend}; entry.views[descriptor] = view }
 j.backends[descriptor] = entry; return view
}
func (j *FakeIPRuntimeJournal) removeUnusedViewLocked(entry *recoveryBackend, descriptor adapter.FakeIPRuntimeBackendDescriptor, view *recoveryBackendView) {
 if view.references != 0 || view.bindings != 0 || (entry.permanent && view.backend == entry.backend) { return }
 delete(j.backends, descriptor); delete(entry.views, descriptor)
}
func (j *FakeIPRuntimeJournal) removeEntryLocked(entry *recoveryBackend) {
 for descriptor, view := range entry.views {
  if entry.permanent && view.backend == entry.backend { continue }
  delete(j.backends, descriptor); delete(entry.views, descriptor)
 }
}
func (j *FakeIPRuntimeJournal) ResolveFakeIPRuntime(ctx context.Context, descriptor adapter.FakeIPRuntimeBackendDescriptor) (adapter.FakeIPRuntimeBackend, func() error, error) {
 j.maintenance.Lock(); defer j.maintenance.Unlock()
 j.access.Lock()
 if j.closed { j.access.Unlock(); return nil, nil, ErrFakeIPRecoveryClosed }
 entry := j.backends[descriptor]; j.access.Unlock()
 if entry == nil {
  // Check the grant before opening a path OR adding a logical alias.
  err := j.runtimeView(func(tx *bbolt.Tx) error {
   root, err := runtimeRoot(tx); if err != nil { return err }
   var granted adapter.FakeIPRuntimeBackendDescriptor
   if err = readRuntimeJSON(root.Bucket(bucketRuntimeCustody), []byte(descriptor.DatabaseID+"\x00"+descriptor.CacheID), &granted); err != nil { return ErrFakeIPRecoveryCustody }
   if granted != descriptor { return ErrFakeIPRecoveryCustody }; return nil
  })
  if err != nil { return nil, nil, err }
  j.access.Lock(); entry, err = j.physicalBackendLocked(descriptor); j.access.Unlock(); if err != nil { return nil, nil, err }
  if entry != nil {
   physical := physicalRuntimeCache(entry.backend); if physical == nil { return nil, nil, ErrFakeIPRuntimeIdentity }
   j.access.Lock(); j.addViewLocked(entry, descriptor, &fakeIPRuntimeBackendView{physical: physical, descriptor: descriptor}); j.access.Unlock()
  } else {
   cache, err := openStrictRuntimeCache(ctx, j.logger, descriptor.Path, descriptor.CacheID, nil); if err != nil { return nil, nil, err }
   // Never initialize an identity in a replacement file during recovery.
   err = cache.runtimeView(func(tx *bbolt.Tx) error { root, err := runtimeRoot(tx); if err != nil { return err }; if string(root.Get(keyRuntimeIdentity)) != descriptor.DatabaseID { return ErrFakeIPRuntimeIdentity }; return nil })
   if err != nil { _ = closeStrictRuntimeCache(cache); return nil, nil, err }
   entry = &recoveryBackend{backend: cache, owned: cache, changed: make(chan struct{})}
   j.access.Lock(); j.addViewLocked(entry, descriptor, cache); j.access.Unlock()
  }
 }
 j.access.Lock()
 if entry.retiring { j.access.Unlock(); return nil, nil, ErrFakeIPRecoveryBusy }
 if entry.failure != nil { err := entry.failure; j.access.Unlock(); return nil, nil, err }
 view := entry.views[descriptor]; if view == nil { view = j.addViewLocked(entry, descriptor, entry.backend) }
 entry.references++; view.references++; j.access.Unlock()
 var once sync.Once; var releaseErr error
 return view.backend, func() error {
  once.Do(func() {
   j.maintenance.Lock(); defer j.maintenance.Unlock()
   j.access.Lock(); entry.references--; view.references--
   if entry.changed != nil { close(entry.changed); entry.changed = make(chan struct{}) }
   last := entry.references == 0 && entry.bindings == 0 && entry.owned != nil
   if !last { j.removeUnusedViewLocked(entry, descriptor, view) }
   j.access.Unlock()
   if last {
    releaseErr = closeStrictRuntimeCache(entry.owned)
    j.access.Lock(); if releaseErr == nil { j.removeEntryLocked(entry) } else { entry.failure = releaseErr }; j.access.Unlock()
   }
  })
  return releaseErr
 }, nil
}
func (j *FakeIPRuntimeJournal) Close() error {
	j.maintenance.Lock(); defer j.maintenance.Unlock()
	j.access.Lock()
	if j.closed { err := j.closeErr; j.access.Unlock(); return err }
	for _, backend := range j.backends { if backend.references != 0 || backend.bindings != 0 || backend.failure != nil { j.access.Unlock(); return ErrFakeIPRecoveryBusy } }
	j.closed = true; j.access.Unlock()
	j.cancel(); <-j.flushDone
	j.flushTimer.Stop()
	j.closeErr = closeStrictRuntimeCache(j.CacheFile)
	return j.closeErr
}

var _ adapter.FakeIPRuntimeResolver = (*FakeIPRuntimeJournal)(nil)

// PruneUnreferencedCustody follows recovery or completed maintenance. A current
// binding/borrow or any durable link retains its grant. It never opens a path;
// abandoned data in an unopened file is reclaimed only if that file is later
// explicitly configured/opened. No per-candidate path history is kept forever.
func (j *FakeIPRuntimeJournal) PruneUnreferencedCustody(ctx context.Context) error {
 if err := ctx.Err(); err != nil { return err }
 j.maintenance.Lock(); defer j.maintenance.Unlock()
 j.access.Lock(); if j.closed { j.access.Unlock(); return ErrFakeIPRecoveryClosed }
 keep := make(map[adapter.FakeIPRuntimeBackendDescriptor]bool); for descriptor := range j.backends { keep[descriptor]=true }; j.access.Unlock()
 return j.runtimeUpdate(func(tx *bbolt.Tx) error {
  root, err := runtimeRoot(tx); if err != nil { return err }
  if err = root.Bucket(bucketRuntimeLinks).ForEach(func(_,raw []byte) error { var link adapter.FakeIPRuntimeLink; if err := json.Unmarshal(raw,&link); err != nil { return err }; for _, namespace := range link.Namespaces { keep[namespace.Backend]=true }; return nil }); err != nil { return err }
  custody := root.Bucket(bucketRuntimeCustody); var remove [][]byte
  if err = custody.ForEach(func(key,raw []byte) error { var descriptor adapter.FakeIPRuntimeBackendDescriptor; if err := json.Unmarshal(raw,&descriptor); err != nil { return err }; if !keep[descriptor] { remove=append(remove,append([]byte(nil),key...)) }; return nil }); err != nil { return err }
  for _, key := range remove { if err = custody.Delete(key); err != nil { return err } }; return nil
 })
}
