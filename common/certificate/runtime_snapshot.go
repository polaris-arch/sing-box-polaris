package certificate

import (
 "context"
 "crypto/sha256"
 "crypto/x509"
 "encoding/binary"
 "errors"
 "net"
 "sync"

 "github.com/sagernet/sing-box/adapter"
 C "github.com/sagernet/sing-box/constant"
)

// RootSnapshot is one immutable root generation. It owns its native anchors
// independently of the watcher's lifetime. The transaction transfers one explicit
// reference to its graph/consumer scope; a borrowed CertificateStore never starts
// or closes the shared watcher. Release each successful Snapshot/Retain once.
type RootSnapshot struct {
 mu sync.Mutex
 released bool
 state *rootSnapshotState
}
type rootSnapshotState struct {
 mu sync.Mutex
 refs uint64
 resource adapter.RuntimeResourceID
 revision uint64
 digest [sha256.Size]byte
 kind string
 pool *x509.CertPool
 platform snapshotPlatform
}

var _ adapter.CertificateStore = (*RootSnapshot)(nil)

func newRootSnapshot(id adapter.RuntimeResourceID,revision uint64,kind string,pool *x509.CertPool,pemBytes []byte)(*RootSnapshot,error){
 if pool == nil { return nil,errors.New("certificate snapshot has no root pool") }
 // SystemCertPool deliberately has no public full-certificate export. A hash
 // of Subjects would alias roots with different keys. This digest identifies
 // the exact allocation/generation instead; Equal compares complete pools
 // before advancing revision. Anchor bytes bind the same native generation.
 hash:=sha256.New()
 writePart:=func(value []byte){var size [8]byte;binary.BigEndian.PutUint64(size[:],uint64(len(value)));_,_=hash.Write(size[:]);_,_=hash.Write(value)}
 writePart([]byte(id.Incarnation))
 var sequence [8]byte;binary.BigEndian.PutUint64(sequence[:],id.Sequence);writePart(sequence[:])
 binary.BigEndian.PutUint64(sequence[:],revision);writePart(sequence[:])
 writePart([]byte(kind));writePart(pemBytes)
 var digest [sha256.Size]byte;copy(digest[:],hash.Sum(nil))
 state:=&rootSnapshotState{refs:1,resource:id,revision:revision,digest:digest,kind:kind,pool:pool.Clone()}
 result:=&RootSnapshot{state:state}
 // Allocate all Go snapshot state before acquiring native anchor ownership.
 platform,err:=newSnapshotPlatform(pemBytes);if err!=nil{return nil,err}
 state.platform=platform
 return result,nil
}
func (s *RootSnapshot) Retain()(*RootSnapshot,error){
 s.mu.Lock();defer s.mu.Unlock();if s.released{return nil,net.ErrClosed}
 s.state.mu.Lock();s.state.refs++;s.state.mu.Unlock()
 return &RootSnapshot{state:s.state},nil
}
func (s *RootSnapshot) Release(){
 s.mu.Lock()
 if s.released{s.mu.Unlock();return};s.released=true
 state:=s.state;state.mu.Lock();state.refs--
 var platform snapshotPlatform
 if state.refs==0{platform=state.platform;state.platform=snapshotPlatform{};state.pool=nil}
 state.mu.Unlock();s.mu.Unlock()
 platform.release()
}
func(s *RootSnapshot)Name()string{return "certificate-snapshot"}
func(s *RootSnapshot)Start(adapter.StartStage,*adapter.Scope)error{return s.RuntimeValidate()}
func(s *RootSnapshot)Pool()*x509.CertPool{s.mu.Lock();defer s.mu.Unlock();if s.released{return nil};return s.state.pool.Clone()}
func(s *RootSnapshot)ExclusiveAnchors()bool{return s.state.kind!=C.CertificateStoreSystem}
func(s *RootSnapshot)StoreKind()string{return s.state.kind}
func(s *RootSnapshot)Digest()[sha256.Size]byte{return s.state.digest}
func(s *RootSnapshot)Revision()uint64{return s.state.revision}
func(s *RootSnapshot)RuntimeResourceID()adapter.RuntimeResourceID{return s.state.resource}
func(s *RootSnapshot)RuntimeValidate()error{s.mu.Lock();defer s.mu.Unlock();if s.released{return net.ErrClosed};return nil}

// Snapshot preserves the caller's exact retained store lineage, including an
// old graph continuation. The caller owns the returned immutable reference.
// Install this snapshot, not the mutable Store, as CertificateStore for each
// runtime consumer before its constructor reads RootPoolFromContext.
func(s *Store)Snapshot(ctx context.Context)(*RootSnapshot,error){
 if err:=s.RuntimeValidate();err!=nil{return nil,err}
 _,release,err:=adapter.AcquireRuntimeOperation(ctx,s.runtime.source);if err!=nil{return nil,err};defer release()
 leave,err:=s.runtime.fence.Acquire();if err!=nil{return nil,err};defer leave()
 s.access.RLock();snapshot:=s.latest
 if snapshot==nil{s.access.RUnlock();return nil,net.ErrClosed}
 value,err:=snapshot.Retain();s.access.RUnlock();return value,err
}
