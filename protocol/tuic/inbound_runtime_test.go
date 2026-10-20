package tuic

import (
 "context"
 "errors"
 "net"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/common/listener"
 "github.com/sagernet/sing-box/log"
)

// Pure ownership fixtures. Constructors and preparation must never bind sockets,
// acquire the published graph, or start receiving protocol traffic.
type ingressFixture struct {
 id adapter.RuntimeResourceID
 graphs atomic.Int64
 resources atomic.Int64
 sourceAcquires atomic.Int64
 graphAcquires atomic.Int64
 membership bool
}
type ingressSource struct{ owner *ingressFixture }
func (s ingressSource) ID() adapter.RuntimeResourceID { return s.owner.id }
func (s ingressSource) Acquire() (adapter.RuntimeResourceLease,error) { s.owner.sourceAcquires.Add(1); return nil, errors.New("root source admission must not be used") }
func (f *ingressFixture) Acquire() (adapter.RuntimeLease,error) { f.graphAcquires.Add(1); return nil, errors.New("constructor activated graph admission") }
type ingressGraph struct { adapter.RuntimeLease; owner *ingressFixture; mu sync.Mutex; released bool }
func (g *ingressGraph) Fork() (adapter.RuntimeLease,error) {
 g.mu.Lock(); defer g.mu.Unlock()
 if g.released { return nil, net.ErrClosed }
 g.owner.graphs.Add(1)
 return &ingressGraph{owner:g.owner},nil
}
func (g *ingressGraph) RetainResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease,error) {
 g.mu.Lock(); defer g.mu.Unlock()
 if g.released || !g.owner.membership || id != g.owner.id { return nil, net.ErrClosed }
 g.owner.resources.Add(1)
 return &ingressResource{owner:g.owner},nil
}
func (g *ingressGraph) Release() { g.mu.Lock(); defer g.mu.Unlock(); if !g.released { g.released=true; g.owner.graphs.Add(-1) } }
type ingressResource struct { owner *ingressFixture; mu sync.Mutex; released bool }
func (r *ingressResource) ID() adapter.RuntimeResourceID { return r.owner.id }
func (*ingressResource) Retiring() <-chan struct{} { return nil }
func (r *ingressResource) Fork() (adapter.RuntimeResourceLease,error) {
 r.mu.Lock(); defer r.mu.Unlock(); if r.released { return nil,net.ErrClosed }
 r.owner.resources.Add(1); return &ingressResource{owner:r.owner},nil
}
func (r *ingressResource) Release() { r.mu.Lock(); defer r.mu.Unlock(); if !r.released { r.released=true; r.owner.resources.Add(-1) } }
func newIngressFixture() *ingressFixture { return &ingressFixture{id:adapter.RuntimeResourceID{Incarnation:"ingress",Sequence:1},membership:true} }
func (f *ingressFixture) context() (context.Context, *ingressGraph) {
 f.graphs.Add(1); graph:=&ingressGraph{owner:f}
 return adapter.ContextWithRuntimeLease(context.Background(),graph),graph
}
func ingressConstruction(f *ingressFixture) (context.Context,*adapter.Scope) {
 scope:=adapter.NewScope(context.Background(),log.NewNOPFactory().Logger())
 ctx:=adapter.ContextWithConstructionScope(scope.Context(),scope)
 ctx=adapter.ContextWithRuntimePreparation(ctx)
 ctx=adapter.ContextWithRuntimeResourceSource(ctx,ingressSource{f})
 ctx=listener.ContextWithRuntimeBinding(ctx,listener.RuntimeBinding{Admission:f})
 return ctx,scope
}
func ingressWait(t *testing.T, ch <-chan struct{}) { t.Helper(); select { case <-ch: case <-time.After(5*time.Second):t.Fatal("ownership barrier watchdog") } }
func ingressPending(t *testing.T,ch <-chan struct{}) { t.Helper();select { case <-ch:t.Fatal("cleanup completed before the admitted callback");default: } }


func TestRuntimeIngressCallbackPinsExactGraphAndCleanup(t *testing.T) {
 f:=newIngressFixture();construction,scope:=ingressConstruction(f)
 closeEntered:=make(chan struct{})
 state,err:=newInboundRuntime(construction,func()error{close(closeEntered);return nil});if err!=nil { t.Fatal(err) }
 ctx,graph:=f.context();owned,release,err:=state.enter(ctx);if err!=nil { t.Fatal(err) }
 graph.Release()
 // This continuation remains usable after its original incoming handle retires.
 _,nestedRelease,err:=state.enter(owned);if err!=nil { t.Fatal(err) };nestedRelease()
 done:=make(chan struct{});go func(){_ = scope.Close();close(done)}()
 ingressWait(t,closeEntered);ingressPending(t,done)
 if _,_,err:=state.enter(owned);err==nil { t.Fatal("sealed callback boundary reopened") }
 release();release();ingressWait(t,done)
 if f.graphs.Load()!=0||f.resources.Load()!=0||f.sourceAcquires.Load()!=0 { t.Fatal("incorrect continuation accounting") }
}
func TestRuntimeIngressRejectsForeignAndReleasedLineage(t *testing.T) {
 f:=newIngressFixture();construction,scope:=ingressConstruction(f);defer scope.Close()
 state,err:=newInboundRuntime(construction,func()error{return nil});if err!=nil { t.Fatal(err) }
 ctx,graph:=f.context();f.membership=false
 if _,_,err:=state.enter(ctx);err==nil { t.Fatal("foreign graph accepted") }
 f.membership=true;graph.Release()
 if _,_,err:=state.enter(ctx);err==nil { t.Fatal("released graph reopened") }
 if _,_,err:=state.enter(context.Background());err==nil { t.Fatal("missing graph silently admitted") }
 if f.sourceAcquires.Load()!=0||f.graphs.Load()!=0||f.resources.Load()!=0 { t.Fatal("fallback admission or failed-acquire leak") }
}
func TestRuntimeIngressPreparationErrorIsStickyAndJoined(t *testing.T) {
 f:=newIngressFixture();construction,scope:=ingressConstruction(f)
 entered,proceed:=make(chan struct{}),make(chan struct{})
 closeEntered:=make(chan struct{})
 state,err:=newInboundRuntime(construction,func()error{close(closeEntered);return nil});if err!=nil { t.Fatal(err) }
 sentinel:=errors.New("private protocol preparation failed")
 result:=make(chan error,1);go func(){result<-state.prepare(func()error{close(entered);<-proceed;return sentinel})}()
 ingressWait(t,entered)
 done:=make(chan struct{});go func(){_ = scope.Close();close(done)}()
 ingressPending(t,closeEntered)
 close(proceed)
 if err:=<-result;!errors.Is(err,sentinel){t.Fatal(err)}
 ingressWait(t,done)
 if err:=state.prepare(func()error{t.Fatal("closed preparation restarted");return nil});err==nil {t.Fatal("closed preparation accepted")}
}

func TestRuntimeIngressConstructionCloseWaitsForReturn(t *testing.T) {
 f:=newIngressFixture();construction,scope:=ingressConstruction(f)
 entered:=make(chan struct{})
 state,finish,err:=newInboundRuntimeConstruction(construction,func()error{close(entered);return nil})
 if err!=nil{t.Fatal(err)}
 _ = state.callbacks.Close()
 done:=make(chan struct{});go func(){_ = scope.Close();close(done)}()
 ingressPending(t,entered);ingressPending(t,done)
 finish();finish();ingressWait(t,entered);ingressWait(t,done)
}
func TestRuntimeIngressCanceledConstructionRegistrationDoesNotSelfWait(t *testing.T) {
 f:=newIngressFixture();construction,scope:=ingressConstruction(f)
 if err:=scope.Close();err!=nil{t.Fatal(err)}
 entered:=make(chan struct{})
 state,finish,err:=newInboundRuntimeConstruction(construction,func()error{close(entered);return nil})
 if err==nil{t.Fatal("canceled construction accepted")}
 if state==nil{t.Fatal("immediate registration lost its cleanup observer")}
 ingressPending(t,entered)
 finish();ingressWait(t,entered)
 if err:=state.callbacks.Wait();err!=nil{t.Fatal(err)}
}
func TestRuntimeIngressConstructorPanicReleasesReturnGate(t *testing.T) {
 f:=newIngressFixture();construction,scope:=ingressConstruction(f)
 entered:=make(chan struct{})
 var recovered any
 func(){
  defer func(){recovered=recover()}()
  state,finish,err:=newInboundRuntimeConstruction(construction,func()error{close(entered);return nil})
  if err!=nil{t.Fatal(err)}
  defer finish()
  _ = state.callbacks.Close()
  ingressPending(t,entered)
  panic("constructor observer panicked")
 }()
 if recovered==nil{t.Fatal("observer panic was swallowed")}
 ingressWait(t,entered)
 if err:=scope.Close();err!=nil{t.Fatal(err)}
}

func TestRuntimeTaskCapturesBeforePublicationAndJoins(t *testing.T){
 f:=newIngressFixture();construction,scope:=ingressConstruction(f)
 state,err:=newInboundRuntime(construction,func()error{return nil});if err!=nil{t.Fatal(err)}
 ctx,graph:=f.context();entered,proceed:=make(chan struct{}),make(chan struct{})
 if !state.runTask(ctx,func(owned context.Context){close(entered);<-proceed;lease,_:=adapter.RuntimeLeaseFromContext(owned);fork,err:=lease.Fork();if err!=nil{t.Error(err)}else{fork.Release()}}){t.Fatal("task rejected")}
 graph.Release();ingressWait(t,entered)
 done:=make(chan struct{});go func(){_ = scope.Close();close(done)}()
 ingressPending(t,done);close(proceed);ingressWait(t,done)
 if f.graphs.Load()!=0||f.resources.Load()!=0||f.sourceAcquires.Load()!=0{t.Fatal("task ownership did not drain exactly")}
}
func TestRuntimeBackgroundWorkerCannotGrantRequestLineage(t *testing.T){
 f:=newIngressFixture();construction,scope:=ingressConstruction(f);defer scope.Close()
 state,err:=newInboundRuntime(construction,func()error{return nil});if err!=nil{t.Fatal(err)}
 invoked:=false
 if state.runTask(context.WithValue(construction,struct{}{},true),func(context.Context){invoked=true}){t.Fatal("unadmitted request task accepted")}
 if invoked||f.sourceAcquires.Load()!=0{t.Fatal("constructor source used as request admission")}
 done:=make(chan struct{})
 if !state.runTask(state.ctx,func(ctx context.Context){if _,ok:=adapter.RuntimeLeaseFromContext(ctx);ok{t.Error("accept worker owns request graph")};close(done)}){t.Fatal("private accept worker rejected")}
 ingressWait(t,done)
}
func TestRuntimeTaskPanicRemainsStickyButActualWorkerJoins(t *testing.T){
 f:=newIngressFixture();construction,scope:=ingressConstruction(f)
 state,err:=newInboundRuntime(construction,func()error{return nil});if err!=nil{t.Fatal(err)}
 ctx,graph:=f.context()
 if !state.runTask(ctx,func(context.Context){panic("task fixture")}){t.Fatal("task rejected")}
 graph.Release();ingressWait(t,state.failed)
 if err:=scope.Close();err==nil{t.Fatal("task panic certified clean retirement")}
 if err:=state.closeAndWait();err==nil{t.Fatal("uncertainty was not sticky")}
 if f.graphs.Load()==0||f.resources.Load()==0{t.Fatal("uncertain operation released exact reservations")}
}
func TestRuntimeCallbackPanicRetainsOwnershipAndJoinsInvocation(t *testing.T){
 f:=newIngressFixture();construction,scope:=ingressConstruction(f)
 state,err:=newInboundRuntime(construction,func()error{return nil});if err!=nil{t.Fatal(err)}
 ctx,graph:=f.context()
 func(){defer func(){if recover()==nil{t.Error("callback panic swallowed")}}();_,release,err:=state.enter(ctx);if err!=nil{t.Fatal(err)};defer release();panic("callback fixture")}()
 graph.Release()
 if err:=scope.Close();err==nil{t.Fatal("callback panic certified clean retirement")}
 if f.graphs.Load()==0||f.resources.Load()==0{t.Fatal("uncertain callback released exact reservations")}
}
