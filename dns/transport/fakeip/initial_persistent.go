package fakeip

import (
 "context"
 "errors"
 "net/netip"
 "sync"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/dns/transport/lifecycle"
 "github.com/sagernet/sing/service"
)

var ErrInitialPersistentBindingRequired = errors.New("initial persistent fake-IP allocator must bind after the stable cache initializes")
var ErrInitialPersistentMetadata = errors.New("persistent fake-IP allocation metadata is incompatible or incomplete; restart/migration decision required")

type fixedPersistentSnapshot interface {
 SnapshotFakeIP(context.Context) (adapter.FakeIPStorageSnapshot, error)
}
type fixedPersistentPreparation struct {
 mu sync.Mutex // serializes initialization I/O, never the publication fence
 cache adapter.CacheFile
 snapshot fixedPersistentSnapshot
 ready bool // manager.mappingAccess
}

// PrepareInitialPersistentRanges creates a private, nonallocating handle for
// the initial graph only. The physical cache may still be unopened. It neither
// reads nor resets that cache, and deliberately has no in-memory fallback.
func (m *Manager) PrepareInitialPersistentRanges(ctx context.Context, inet4Range, inet6Range netip.Prefix, cache adapter.CacheFile) (*RangeMigration, error) {
 if err:=ctx.Err();err!=nil{return nil,err}
 if err:=validRanges(inet4Range,inet6Range);err!=nil{return nil,err}
 if cache==nil || !cache.StoreFakeIP() || service.FromContext[adapter.CacheFile](m.store.ctx)!=cache { return nil,ErrInitialPersistentMetadata }
 snapshot,ok:=cache.(fixedPersistentSnapshot);if !ok{return nil,ErrInitialPersistentMetadata}
 done,ok:=m.work.Reserve();if !ok{return nil,lifecycle.ErrStopped}
 m.mappingAccess.Lock();defer m.mappingAccess.Unlock()
 if !m.started.Load(){done();return nil,ErrManagerNotStarted}
 if !m.active.empty || m.preparing!=nil || m.recovered!=nil || len(m.transitions)!=0 || m.authority!=nil {done();return nil,ErrPersistentMigrationRequired}
 for _,namespace:=range m.namespaces {if namespace!=m.active && !namespace.aborted {done();return nil,ErrPersistencePreparing}}
 if m.nextNamespace==^uint64(0){done();return nil,ErrMigrationStale}
 m.nextNamespace++
 store:=NewStore(m.store.ctx,m.store.logger,inet4Range.Masked(),inet6Range.Masked())
 namespace:=&memoryNamespace{id:m.nextNamespace,store:store,owned:make(map[netip.Addr]struct{})}
 m.namespaces[namespace.id]=namespace
 return &RangeMigration{manager:m,namespace:namespace,base:m.active,permit:NewAnswerPermit(),done:done,initial:&fixedPersistentPreparation{cache:cache,snapshot:snapshot}},nil
}

// InitializePersistentStorage follows successful stable CacheFile Initialize,
// before graph DNS startup/commit. Snapshot I/O is outside manager/publication
// locks. Compatible legacy cursor and backing identity are preserved exactly.
// A truly new empty database seeds the original first-address cursor without
// writing metadata; ordinary first allocation reserves its normal cursor block.
func (c *RangeMigration) InitializePersistentStorage(ctx context.Context) error {
 initial:=c.initial
 if initial==nil{return nil}
 initial.mu.Lock();defer initial.mu.Unlock()
 m:=c.manager
 done,ok:=m.work.Reserve();if !ok{return lifecycle.ErrStopped};defer done()
 m.mappingAccess.Lock()
 if initial.ready {m.mappingAccess.Unlock();return nil}
 valid:=c.state.Load()==0 && m.active==c.base && c.base.empty && !c.namespace.aborted && m.recovered==nil && m.preparing==nil
 m.mappingAccess.Unlock()
 if !valid{return ErrMigrationStale}
 snapshot,err:=initial.snapshot.SnapshotFakeIP(ctx)
 if err!=nil{return err}
 metadata,err:=fixedInitialMetadata(c.namespace.store,snapshot)
 if err!=nil{return err}
 if err=ctx.Err();err!=nil{return err}
 m.mappingAccess.Lock();defer m.mappingAccess.Unlock()
 if c.state.Load()!=0 || m.active!=c.base || c.namespace.aborted || m.recovered!=nil || m.preparing!=nil {return ErrMigrationStale}
 store:=c.namespace.store
 store.storage=initial.cache
 store.inet4Current,store.inet6Current=metadata.Inet4Current,metadata.Inet6Current
 initial.ready=true
 return nil
}
func fixedInitialMetadata(store *Store,snapshot adapter.FakeIPStorageSnapshot)(adapter.FakeIPMetadata,error){
 metadata:=adapter.FakeIPMetadata{Inet4Range:store.inet4Range,Inet6Range:store.inet6Range}
 if snapshot.Metadata==nil {
  if len(snapshot.Mappings)!=0 || len(snapshot.Answers)!=0 || len(snapshot.PendingAnswers)!=0 {return metadata,ErrInitialPersistentMetadata}
  if store.inet4Range.IsValid(){metadata.Inet4Current=store.inet4Range.Addr().Next()}
  if store.inet6Range.IsValid(){metadata.Inet6Current=store.inet6Range.Addr().Next()}
  return metadata,nil
 }
 metadata=*snapshot.Metadata
 if metadata.Inet4Range!=store.inet4Range || metadata.Inet6Range!=store.inet6Range {return metadata,ErrInitialPersistentMetadata}
 validCursor:=func(prefix netip.Prefix,last,current netip.Addr)bool{
  if !prefix.IsValid(){return !current.IsValid()}
  return current.IsValid() && prefix.Contains(current) && current!=prefix.Addr() && current!=last
 }
 if !validCursor(store.inet4Range,store.inet4Last,metadata.Inet4Current) || !validCursor(store.inet6Range,store.inet6Last,metadata.Inet6Current){return metadata,ErrInitialPersistentMetadata}
 if len(snapshot.Answers)!=0 || len(snapshot.PendingAnswers)!=0 {return metadata,ErrPersistentMigrationRequired}
 domains:=make(map[domainKey]bool)
 for address,domain:=range snapshot.Mappings{
  if domain=="" || (!usable(store.inet4Range,address) && !usable(store.inet6Range,address)){return metadata,ErrInitialPersistentMetadata}
  key:=domainKey{domain,address.Is6()};if domains[key]{return metadata,ErrInitialPersistentMetadata};domains[key]=true
 }
 return metadata,nil
}
