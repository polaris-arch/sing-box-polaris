package cachefile

import (
 "context"
 "encoding/binary"
 "errors"
 "fmt"
 "strings"
 "sync"
 "time"

 "github.com/sagernet/bbolt"
 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing/common/logger"
)

// DNSRuntimeViewOptions applies only to the logical DNS client. Namespace must
// be a stable digest of the DNS dependency/configuration closure, not a revision
// number or a transport display tag. Physical path/cache ID remain unchanged.
type DNSRuntimeViewOptions struct {
 Namespace string
 DisableExpire bool
 OptimisticTimeout time.Duration
}

// DNSRuntimeView owns private buffering and immutable policy over one retained
// physical DB. It neither opens a DB nor calls CacheFile.Start. New views may
// read existing entries but cannot mutate persistence until Activate.
type DNSRuntimeView struct {
 physical *CacheFile
 store *CacheFile
 prefix string
 mu sync.Mutex
 closed, active, prepared bool
 operations sync.WaitGroup
 workers sync.WaitGroup
 activate chan struct{}
 stop chan struct{}
 closeOnce sync.Once
 closeErr error
 release func()
}

func (c *CacheFile) retainRuntimeClient() (func(), error) {
 c.runtimeClients.Lock()
 defer c.runtimeClients.Unlock()
 if c.runtimeClientsClosing { return nil, errors.New("cache physical owner is closing") }
 c.runtimeClientsReserved = true
 c.runtimeClientRefs.Add(1)
 var once sync.Once
 return func() { once.Do(c.runtimeClientRefs.Done) }, nil
}
func (c *CacheFile) closeRuntimeDatabase() error {
 c.runtimeClients.Lock(); c.runtimeClientsClosing = true; c.runtimeClients.Unlock()
 c.runtimeClientRefs.Wait()
 c.dbAccess.Lock(); defer c.dbAccess.Unlock()
 if c.DB == nil { return nil }
 return c.DB.Close()
}

func (c *CacheFile) NewDNSRuntimeView(ctx context.Context, options DNSRuntimeViewOptions) (*DNSRuntimeView, error) {
 if err := ctx.Err(); err != nil { return nil, err }
 if options.Namespace == "" || strings.ContainsRune(options.Namespace, '\x00') { return nil, errors.New("DNS runtime view needs a nonempty semantic namespace without NUL") }
 release, err := c.retainRuntimeClient()
 if err != nil { return nil, err }
 timer := time.NewTimer(time.Hour); timer.Stop()
 store := &CacheFile{ctx: context.Background(), logger: c.logger, path: c.path,
  cacheID: append([]byte(nil), c.cacheID...), cacheIDText: c.cacheIDText,
  storeDNS: c.storeDNS, storeRDRC: c.storeRDRC, disableExpire: options.DisableExpire,
  optimisticTimeout: options.OptimisticTimeout, rdrcTimeout: c.rdrcTimeout,
  bufferSize: c.bufferSize, flushInterval: c.flushInterval,
  pending: newPendingWrites(), flushTimer: timer, flushSignal: make(chan struct{}, 1)}
 store.runtimeStrict.Store(true)
 v := &DNSRuntimeView{physical: c, store: store, prefix: "hot-dns\x00" + options.Namespace + "\x00", activate: make(chan struct{}), stop: make(chan struct{}), release: release}
 v.workers.Add(1)
 go v.run()
 return v, nil
}
// Prepare is called after the one stable physical cache has initialized. It
// checks the actual DB under its owner lock without starting cleanup or writes.
func (v *DNSRuntimeView) Prepare() error {
 v.mu.Lock(); defer v.mu.Unlock()
 if v.closed { return errors.New("DNS runtime view is closed") }
 if v.prepared { return nil }
 v.physical.dbAccess.Lock(); defer v.physical.dbAccess.Unlock()
 if v.physical.DB == nil { return errors.New("cache physical owner is not open") }
 v.physical.runtimeStrict.Store(true)
 v.store.DB = v.physical.DB
 v.prepared = true
 return nil
}
func (v *DNSRuntimeView) StoreDNS() bool { return v.store.storeDNS }
func (v *DNSRuntimeView) StoreRDRC() bool { return v.store.storeRDRC }
func (v *DNSRuntimeView) RuntimeDNSPhysicalCache() adapter.CacheFile { return v.physical }
func (v *DNSRuntimeView) Activate() {
 v.mu.Lock(); defer v.mu.Unlock()
 if !v.closed && v.prepared && !v.active { v.active = true; close(v.activate) }
}
func (v *DNSRuntimeView) enter(write bool) (func(), bool) {
 v.mu.Lock(); defer v.mu.Unlock()
 if v.closed || !v.prepared || (write && !v.active) { return nil, false }
 v.operations.Add(1)
 return v.operations.Done, true
}
func (v *DNSRuntimeView) LoadDNSCache(transport, name string, qtype uint16) ([]byte, time.Time, bool) {
 leave, ok := v.enter(false); if !ok { return nil, time.Time{}, false }; defer leave()
 if !v.StoreDNS() { return nil, time.Time{}, false }
 return v.store.LoadDNSCache(v.prefix+transport, name, qtype)
}
func (v *DNSRuntimeView) SaveDNSCache(transport, name string, qtype uint16, message []byte, expiry time.Time) error {
 leave, ok := v.enter(true); if !ok { return errors.New("DNS runtime view is private or closed") }; defer leave()
 if !v.StoreDNS() { return nil }
 v.store.queueDNSCache(v.prefix+transport, name, qtype, message, expiry)
 return v.flush()
}
func (v *DNSRuntimeView) SaveDNSCacheAsync(transport, name string, qtype uint16, message []byte, expiry time.Time, _ logger.Logger) {
 leave, ok := v.enter(true); if !ok { return }; defer leave()
 if v.StoreDNS() { v.store.queueDNSCache(v.prefix+transport, name, qtype, message, expiry) }
}
func (v *DNSRuntimeView) LoadRDRC(transport, name string, qtype uint16) bool {
 leave, ok := v.enter(false); if !ok { return false }; defer leave()
 return v.StoreRDRC() && v.store.LoadRDRC(v.prefix+transport, name, qtype)
}
func (v *DNSRuntimeView) SaveRDRC(transport, name string, qtype uint16) error {
 leave, ok := v.enter(true); if !ok { return errors.New("DNS runtime view is private or closed") }; defer leave()
 if !v.StoreRDRC() { return nil }
 v.store.queueRDRC(v.prefix+transport, name, qtype)
 return v.flush()
}
func (v *DNSRuntimeView) SaveRDRCAsync(transport, name string, qtype uint16, _ logger.Logger) {
 leave, ok := v.enter(true); if !ok { return }; defer leave()
 if v.StoreRDRC() { v.store.queueRDRC(v.prefix+transport, name, qtype) }
}

// flush preserves all failed DNS/RDRC writes, not just fake-IP records. Newer
// pending answers win over the failed batch. No detached goroutine owns I/O.
func (v *DNSRuntimeView) flush() error {
 c := v.store
 c.flushAccess.Lock(); defer c.flushAccess.Unlock()
 c.pendingAccess.Lock()
 if c.pending.count == 0 { c.pendingAccess.Unlock(); return nil }
 writing := c.pending; c.writing = writing; c.pending = newPendingWrites()
 c.pendingAccess.Unlock()
 err := v.physical.runtimeUpdate(func(tx *bbolt.Tx) error { return c.writePending(tx, writing) })
 c.pendingAccess.Lock()
 if err != nil {
  for key, value := range writing.dnsCache { if _, newer := c.pending.dnsCache[key]; !newer { c.pending.dnsCache[key] = value; c.pending.count++; c.pending.size += len(key.QuestionName)+len(value.value) } }
  for key := range writing.rdrc { if _, newer := c.pending.rdrc[key]; !newer { c.pending.rdrc[key] = struct{}{}; c.pending.count++; c.pending.size += len(key.QuestionName) } }
 }
 c.writing = nil
 c.pendingAccess.Unlock()
 return err
}
func (v *DNSRuntimeView) ClearDNSCache() error {
 leave, ok := v.enter(true); if !ok { return errors.New("DNS runtime view is private or closed") }; defer leave()
 c := v.store
 c.flushAccess.Lock(); defer c.flushAccess.Unlock()
 err := v.physical.runtimeUpdate(func(tx *bbolt.Tx) error {
  bucket := c.bucket(tx, bucketDNSCache); if bucket == nil { return nil }
  var names [][]byte
  if err := bucket.ForEachBucket(func(name []byte) error { if strings.HasPrefix(string(name), v.prefix) { names = append(names, append([]byte(nil), name...)) }; return nil }); err != nil { return err }
  for _, name := range names { if err := bucket.DeleteBucket(name); err != nil { return err } }
  return nil
 })
 if err != nil { return err }
 c.pendingAccess.Lock(); defer c.pendingAccess.Unlock()
 for key, entry := range c.pending.dnsCache { c.pending.count--; c.pending.size -= len(key.QuestionName)+len(entry.value) }
 clear(c.pending.dnsCache)
 return nil
}
func (v *DNSRuntimeView) run() {
 defer v.workers.Done()
 select { case <-v.stop: return; case <-v.activate: }
 interval := v.store.optimisticTimeout / 2
 if interval <= 0 { interval = time.Hour }
 if !v.StoreDNS() && v.StoreRDRC() && v.store.rdrcTimeout > 0 { interval = v.store.rdrcTimeout / 2 }
 if interval <= 0 { interval = time.Hour }
 ticker := time.NewTicker(interval); defer ticker.Stop()
 for {
  select {
  case <-v.stop: return
  case <-v.store.flushTimer.C:
  case <-v.store.flushSignal:
  case <-ticker.C:
   if err := v.cleanup(); err != nil { v.store.logger.Warn("cleanup private DNS cache: ", err) }
  }
  if err := v.flush(); err != nil { v.store.logger.Warn("flush private DNS cache: ", err) }
 }
}
func (v *DNSRuntimeView) cleanup() error {
 now := time.Now()
 return v.physical.runtimeUpdate(func(tx *bbolt.Tx) error {
  for _, kind := range []struct { key []byte; enabled bool; dns bool }{{bucketDNSCache,v.StoreDNS(),true},{bucketRDRC,v.StoreRDRC(),false}} {
   if !kind.enabled { continue }
   bucket := v.store.bucket(tx, kind.key); if bucket == nil { continue }
   err := bucket.ForEachBucket(func(name []byte) error {
    if !strings.HasPrefix(string(name),v.prefix) { return nil }
    entries := bucket.Bucket(name); if entries == nil { return nil }
    var expired [][]byte
    err := entries.ForEach(func(key,value []byte) error {
     remove := len(value)<8
     if !remove && !(kind.dns && v.store.disableExpire) {
      expiry := time.Unix(int64(binary.BigEndian.Uint64(value[:8])),0)
      if kind.dns { expiry = expiry.Add(v.store.optimisticTimeout) }
      remove = now.After(expiry)
     }
     if remove { expired=append(expired,append([]byte(nil),key...)) }; return nil
    })
    if err != nil { return err }
    for _, key := range expired { if err := entries.Delete(key); err != nil { return err } }
    return nil
   })
   if err != nil { return err }
  }
  return nil
 })
}
func (v *DNSRuntimeView) Close() error {
 v.closeOnce.Do(func() {
  v.mu.Lock(); v.closed = true; close(v.stop); v.mu.Unlock()
  v.workers.Wait()
  v.operations.Wait()
  v.store.flushTimer.Stop()
  if v.prepared { if err := v.flush(); err != nil { v.closeErr = fmt.Errorf("DNS runtime view retained after failed final flush: %v",err); return } }
  v.release()
 })
 return v.closeErr
}
var _ adapter.DNSCacheStore = (*DNSRuntimeView)(nil)
var _ adapter.RDRCStore = (*DNSRuntimeView)(nil)
