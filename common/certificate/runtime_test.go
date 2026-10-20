package certificate

import (
 "context"
 "crypto/x509"
 "encoding/pem"
 "os"
 "path/filepath"
 "sync/atomic"
 "sync"
 "testing"
 "time"

 "github.com/sagernet/sing-box/adapter"
 C "github.com/sagernet/sing-box/constant"
 "github.com/sagernet/sing-box/internal/runtimegraph"
 "github.com/sagernet/sing-box/log"
 "github.com/sagernet/sing-box/option"
 "github.com/sagernet/sing/common/logger"
)

func rootFixturePEMs(t *testing.T)([]byte,[]byte){
 t.Helper();first,rest:=pem.Decode([]byte(mozillaIncludedPEM()));if first==nil{t.Fatal("bundled first root missing")}
 second,_:=pem.Decode(rest);if second==nil{t.Fatal("bundled second root missing")}
 return pem.EncodeToMemory(first),pem.EncodeToMemory(second)
}
func rootStoreFixture(t *testing.T,options option.CertificateOptions)*Store{
 t.Helper();scope:=adapter.NewScope(context.Background(),log.NewNOPFactory().Logger())
 owner,err:=runtimegraph.NewResourceOwner(context.Background(),adapter.RuntimeResourceID{Incarnation:"root-snapshot-fixture",Sequence:1},nil,scope.Close);if err!=nil{t.Fatal(err)}
 construction,err:=owner.Acquire();if err!=nil{t.Fatal(err)}
 ctx:=adapter.ContextWithRuntimePreparation(adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(),scope),owner))
 store,err:=NewStore(ctx,log.NewNOPFactory().Logger(),options);if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){owner.Seal();construction.Release();wait,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel();if err:=owner.WaitClosed(wait);err!=nil{t.Error(err)}})
 return store
}
func rootSnapshotFixture(t *testing.T,store *Store)*RootSnapshot{t.Helper();snapshot,err:=store.Snapshot(context.Background());if err!=nil{t.Fatal(err)};t.Cleanup(snapshot.Release);return snapshot}
func TestRootSnapshotHasIndependentIdempotentReferencesAndPoolCopies(t *testing.T){
 first,second:=rootFixturePEMs(t)
 store:=rootStoreFixture(t,option.CertificateOptions{Store:C.CertificateStoreNone,Certificate:[]string{string(first)}})
 a:=rootSnapshotFixture(t,store);b,err:=a.Retain();if err!=nil{t.Fatal(err)};defer b.Release()
 before:=b.Pool();mutable:=a.Pool();if !mutable.AppendCertsFromPEM(second){t.Fatal("fixture root failed")}
 if !before.Equal(b.Pool())||mutable.Equal(b.Pool()){t.Fatal("snapshot returned its mutable pool")}
 a.Release();a.Release()
 if _,err:=a.Retain();err==nil||a.Pool()!=nil{t.Fatal("released snapshot reference reopened")}
 if b.Pool()==nil{t.Fatal("duplicate release consumed another snapshot reference")}
 if a.Digest()!=b.Digest()||a.Revision()!=b.Revision()||a.RuntimeResourceID()!=b.RuntimeResourceID(){t.Fatal("retained snapshot changed generation")}
 if err:=store.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
 if !before.Equal(b.Pool()){t.Fatal("store retirement invalidated an independently retained generation")}
}
func TestRootWatchCandidateNeverMutatesActiveSnapshotAndCoalesces(t *testing.T){
 first,second:=rootFixturePEMs(t);path:=filepath.Join(t.TempDir(),"roots.pem")
 if err:=os.WriteFile(path,first,0o600);err!=nil{t.Fatal(err)}
 store:=rootStoreFixture(t,option.CertificateOptions{Store:C.CertificateStoreNone,CertificatePath:[]string{path}})
 active:=rootSnapshotFixture(t,store);activePool:=active.Pool();revision:=active.Revision()
 // Invoke the exact watcher callback body deterministically; real fsnotify
 // event timing is deliberately not used as a readiness or completion oracle.
 if err:=os.WriteFile(path,second,0o600);err!=nil{t.Fatal(err)}
 if err:=store.update();err!=nil{t.Fatal(err)}
 candidate:=rootSnapshotFixture(t,store)
 if candidate.Revision()!=revision+1||candidate.Digest()==active.Digest(){t.Fatal("changed root generation not identified")}
 if !activePool.Equal(active.Pool())||active.Pool().Equal(candidate.Pool()){t.Fatal("private reload mutated active graph roots")}
 if err:=os.WriteFile(path,append(append([]byte(nil),first...),second...),0o600);err!=nil{t.Fatal(err)}
 if err:=store.update();err!=nil{t.Fatal(err)}
 if len(store.runtime.changes)!=1{t.Fatal("watch notification burst was not bounded")}
 select{case <-store.RuntimeChanges():default:t.Fatal("root transaction notification absent")}
 stable:=rootSnapshotFixture(t,store)
 if err:=store.update();err!=nil{t.Fatal(err)}
 if store.RuntimeRevision()!=stable.Revision()||len(store.runtime.changes)!=0{t.Fatal("identical root contents created another generation")}
 if err:=os.WriteFile(path,[]byte("invalid PEM"),0o600);err!=nil{t.Fatal(err)}
 if err:=store.update();err==nil{t.Fatal("invalid candidate accepted")}
 after:=rootSnapshotFixture(t,store)
 if after.Digest()!=stable.Digest()||len(store.runtime.changes)!=0{t.Fatal("failed candidate changed roots or notified publication")}
}

type blockingRootLogger struct{logger.Logger;entered chan struct{};finish chan struct{};calls atomic.Int32}
func(l *blockingRootLogger)Error(...any){l.calls.Add(1);close(l.entered);<-l.finish}
func TestRootStoreCloseDrainsActualLoggerCallbackAndRejectsLateReload(t *testing.T){
 store:=rootStoreFixture(t,option.CertificateOptions{Store:C.CertificateStoreNone})
 active:=rootSnapshotFixture(t,store)
 base:=&blockingRootLogger{Logger:log.NewNOPFactory().Logger(),entered:make(chan struct{}),finish:make(chan struct{})}
 guarded:=&runtimeStoreLogger{Logger:base,fence:store.runtime.callbacks}
 exited:=make(chan struct{})
 var releaseOnce sync.Once
 releaseFinish:=func(){releaseOnce.Do(func(){close(base.finish)})}
 t.Cleanup(func(){releaseFinish();select{case <-exited:case <-time.After(5*time.Second):t.Error("logger fixture did not unwind")}})
 go func(){guarded.Error("watcher error");close(exited)}()
 select{case <-base.entered:case <-time.After(5*time.Second):t.Fatal("logger callback not entered")}
 store.RuntimeStop()
 closed:=make(chan error,1);go func(){closed<-store.RuntimeCloseAndWait()}()
 select{case <-closed:t.Fatal("store forgot admitted logger callback");default:}
 releaseFinish()
 select{case <-exited:case <-time.After(5*time.Second):t.Fatal("logger callback did not return")}
 select{case err:=<-closed:if err!=nil{t.Fatal(err)};case <-time.After(5*time.Second):t.Fatal("store did not join callback")}
 guarded.Error("late watcher tail")
 if base.calls.Load()!=1{t.Fatal("late logger reached retired dependency")}
 if err:=store.update();err==nil{t.Fatal("late watcher body reopened store")}
 if active.Pool()==nil{t.Fatal("active immutable snapshot lost to watcher cleanup")}
}
func TestRootSnapshotDigestCannotAliasDifferentSystemRootGenerations(t *testing.T){
 first,second:=rootFixturePEMs(t)
 pool:=x509.NewCertPool();pool.AppendCertsFromPEM(first)
 id:=adapter.RuntimeResourceID{Incarnation:"system-root-fixture",Sequence:7}
 a,err:=newRootSnapshot(id,1,C.CertificateStoreSystem,pool,nil);if err!=nil{t.Fatal(err)};defer a.Release()
 pool.AppendCertsFromPEM(second)
 b,err:=newRootSnapshot(id,2,C.CertificateStoreSystem,pool,nil);if err!=nil{t.Fatal(err)};defer b.Release()
 if a.Digest()==b.Digest(){t.Fatal("distinct exact system root generations aliased")}
 if err:=a.RuntimeValidate();err!=nil{t.Fatal("valid root snapshot rejected",err)}
}
