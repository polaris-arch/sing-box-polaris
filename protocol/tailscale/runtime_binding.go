//go:build with_tailscale

package tailscale

import (
 "context"
 "crypto/tls"
 "errors"
 "net"
 "net/http"
 "sync"
 "time"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/outbound"
 "github.com/sagernet/sing-box/common/dialer"
 "github.com/sagernet/sing/service"
 "github.com/sagernet/sing/common/ntp"
 M "github.com/sagernet/sing/common/metadata"
 runtimeTLS "github.com/sagernet/sing-box/common/tls"
 N "github.com/sagernet/sing/common/network"
)

// A binding belongs to one logical graph generation. Its continuation fence is
// independent of new-root admission. Retirement never seals that fence while
// an original call, response body or native carrier can still fork it.
// Neither this binding nor any native carrier retains its own ResourceOwner.
// Logical cleanup joins this binding before releasing captured dependency edges.
type runtimeEndpointBinding struct {
 mu sync.Mutex
 physical *runtimeEndpointPhysical
 logical *Endpoint
 source adapter.RuntimeResourceSource
 scope *adapter.Scope
 ctx context.Context
 begin func(context.Context) (context.Context, func(), error)
 callbacks *outbound.RuntimeIOFence
 dialer N.Dialer
 dns adapter.DNSRouter
 query adapter.DNSQueryOptions
 router adapter.Router
 transport *http.Transport
 roots bool
 retired bool
 sealed bool
 refs uint64
 quiescent chan struct{}
 closeOnce sync.Once
 closeDone chan struct{}
 closeErr error
}

type runtimeBindingContextKey struct{}
type runtimeBindingContinuation struct {
 binding *runtimeEndpointBinding
 // Borrowed exact capability. AcquireRuntimeOperation must fork it; a released
 // capability fails, without falling through to a newly published binding.
 context context.Context
}

// reserve is called before exposing a root or continuation invocation. Every
// returned carrier/body transfers this slot until its original completion.
func(b *runtimeEndpointBinding)reserve(root bool)(func(),error){
 b.mu.Lock()
 if b.sealed || b.refs==^uint64(0) || root && !b.roots { b.mu.Unlock();return nil,net.ErrClosed }
 b.refs++
 b.mu.Unlock()
 var once sync.Once
 return func(){once.Do(func(){
  b.mu.Lock()
  b.refs--
  if b.retired && b.refs==0 { b.sealed=true;close(b.quiescent) }
  b.mu.Unlock()
 })},nil
}

func(b *runtimeEndpointBinding)acquire(ctx context.Context)(context.Context,func(),error){
 inherited,hasInherited:=ctx.Value(runtimeBindingContextKey{}).(*runtimeBindingContinuation)
 if hasInherited && (inherited==nil || inherited.binding!=b){return nil,nil,errors.New("Tailscale continuation belongs to a different binding")}
 var owned context.Context
 var release func()
 var err error
 if hasInherited {
  // Preserve an existing flow's graph lease as well as its binding. Forking
  // the wrapped capability charges every nested adapter continuation too.
  lease,ok:=adapter.RuntimeResourceLeaseFromContext(inherited.context,b.source.ID())
  if !ok{return nil,nil,errors.New("Tailscale inherited binding capability missing")}
  owned=adapter.ContextWithRuntimeResourceLease(ctx,lease)
  owned,release,err=adapter.AcquireRuntimeOperation(owned,b.source)
 } else {
  leave,reserveErr:=b.reserve(true);if reserveErr!=nil{return nil,nil,reserveErr}
  owned,release,err=b.begin(ctx)
  if err!=nil{leave();return nil,nil,err}
  inner,ok:=adapter.RuntimeResourceLeaseFromContext(owned,b.source.ID())
  if !ok{release();leave();return nil,nil,errors.New("Tailscale registered binding capability missing")}
  lease:=&runtimeBindingLease{binding:b,inner:inner,releaseInner:release,releaseSlot:leave}
  owned=adapter.ContextWithRuntimeResourceLease(owned,lease)
  release=lease.Release
 }
 if err!=nil{return nil,nil,err}
 cancel:=func(){}
 if b.physical!=nil{owned,cancel=b.physical.joinContext(owned)}
 if err=owned.Err();err!=nil{cancel();release();return nil,nil,err}
 owned=context.WithValue(owned,runtimeBindingContextKey{},&runtimeBindingContinuation{binding:b,context:owned})
 var once sync.Once
 return owned,func(){once.Do(func(){cancel();release()})},nil
}

// Wrap the existing registered lease instead of adding a new resource owner.
// Every nested Fork is counted, including forks made by generic adapters that
// know nothing about Tailscale. A raw underlying lease never leaves this type.
type runtimeBindingLease struct{
 mu sync.Mutex
 binding *runtimeEndpointBinding
 inner adapter.RuntimeResourceLease
 releaseInner,releaseSlot func()
 released bool
}
func(l *runtimeBindingLease)ID()adapter.RuntimeResourceID{return l.inner.ID()}
func(l *runtimeBindingLease)Retiring()<-chan struct{}{return l.inner.Retiring()}
func(l *runtimeBindingLease)Fork()(adapter.RuntimeResourceLease,error){
 l.mu.Lock();defer l.mu.Unlock()
 if l.released{return nil,net.ErrClosed}
 leave,err:=l.binding.reserve(false);if err!=nil{return nil,err}
 inner,err:=l.inner.Fork();if err!=nil{leave();return nil,err}
 return &runtimeBindingLease{binding:l.binding,inner:inner,releaseInner:inner.Release,releaseSlot:leave},nil
}
func(l *runtimeBindingLease)RetainResource(id adapter.RuntimeResourceID)(adapter.RuntimeResourceLease,error){
 if id==l.ID(){return l.Fork()}
 l.mu.Lock();defer l.mu.Unlock()
 if l.released{return nil,net.ErrClosed}
 continuation,ok:=l.inner.(adapter.RuntimeResourceContinuation)
 if !ok{return nil,errors.New("Tailscale binding lacks captured dependency continuation")}
 return continuation.RetainResource(id)
}
func(l *runtimeBindingLease)Release(){
 l.mu.Lock();if l.released{l.mu.Unlock();return};l.released=true;l.mu.Unlock()
 l.releaseInner();l.releaseSlot()
}

// retireRoot is infallible admission state only. It does not cancel old
// requests, close native sockets, seal continuation fences or wait under locks.
func(b *runtimeEndpointBinding)retireRoot(){
 b.mu.Lock()
 if !b.retired {
  b.roots=false;b.retired=true
  if b.refs==0 { b.sealed=true;close(b.quiescent) }
 }
 b.mu.Unlock()
}

func(b *runtimeEndpointBinding)closeAndWait()error{
 b.closeOnce.Do(func(){
  b.closeErr=runtimeTLS.NewRuntimeCleanupError(errors.New("Tailscale binding cleanup did not return"))
  defer close(b.closeDone)
  b.retireRoot()
  if b.transport!=nil { b.transport.CloseIdleConnections() }
  // Only original invocations and original carrier/body completion release
  // refs. A blocked native Close leaves this exact generation quarantined.
  <-b.quiescent
  b.closeErr=errors.Join(b.callbacks.RuntimeCloseAndWait(),b.scope.Close())
  if b.closeErr!=nil { b.closeErr=runtimeTLS.NewRuntimeCleanupError(b.closeErr) }
 })
 <-b.closeDone
 return b.closeErr
}

// holdCarrier observes the actual fence completion, never requests early close.
// Callers register with the physical carrier census before invoking this. The
// reservation remains charged on uncertainty instead of releasing dependencies.
func(b *runtimeEndpointBinding)holdCarrier(fence *outbound.RuntimeIOFence,release func()){
 go func(){if err:=fence.Wait();err==nil{release()}}()
}

func(t *Endpoint)newRuntimeBinding(p *runtimeEndpointPhysical)(*runtimeEndpointBinding,error){
 // Private scope survives logical context cancellation until exact retirement.
 // It retains only this generation's immutable services, never a graph lease.
 scope:=adapter.NewScope(context.WithoutCancel(t.ctx),t.logger)
 b:=&runtimeEndpointBinding{physical:p,logical:t,source:t.runtime.source,scope:scope,callbacks:outbound.NewRuntimeIOFence(nil),roots:true,quiescent:make(chan struct{}),closeDone:make(chan struct{}),router:t.router}
 b.ctx=adapter.ContextWithConstructionScope(scope.Context(),scope)
 var err error
 b.begin,err=outbound.RegisterRuntimeOwnedFence(b.ctx,b.callbacks)
 if err!=nil{return nil,errors.Join(err,scope.Close())}
 b.dialer,err=dialer.NewWithOptions(dialer.Options{Context:b.ctx,Options:t.runtime.options.DialerOptions,RemoteIsDomain:true,ResolverOnDetour:true,NewDialer:true})
 if err!=nil{return nil,errors.Join(err,scope.Close())}
 resolver,ok:=b.dialer.(dialer.ResolveDialer)
 if !ok{return nil,errors.Join(errors.New("Tailscale binding dialer lacks query policy"),scope.Close())}
 b.query=resolver.QueryOptions()
 b.dns=service.FromContext[adapter.DNSRouter](b.ctx)
 if b.dns==nil{return nil,errors.Join(errors.New("Tailscale binding lacks DNS router"),scope.Close())}
 // Keep pooled carriers finite after retirement, including an H2 stream that
 // becomes idle after Body.Close returns on request cancellation. Native idle
 // expiry closes only idle carriers; actual Close/method fences prove completion.
 b.transport=&http.Transport{IdleConnTimeout:90*time.Second,ForceAttemptHTTP2:true,DialContext:func(ctx context.Context,network,address string)(net.Conn,error){return b.dial(ctx,network,M.ParseSocksaddr(address))},TLSClientConfig:&tls.Config{RootCAs:adapter.RootPoolFromContext(b.ctx),Time:ntp.TimeFuncFromContext(b.ctx)}}
 scope.Add(func()error{b.transport.CloseIdleConnections();return nil})
 return b,nil
}

func(b *runtimeEndpointBinding)dial(ctx context.Context,network string,destination M.Socksaddr)(net.Conn,error){
 return b.dialWith(ctx,func(owned context.Context)(net.Conn,error){return b.dialer.DialContext(owned,network,destination)})
}

func(b *runtimeEndpointBinding)dialWith(ctx context.Context,next func(context.Context)(net.Conn,error))(net.Conn,error){
 creation,err:=b.physical.carriers.Begin();if err!=nil{return nil,err};defer creation.Done()
 owned,release,err:=b.acquire(ctx);if err!=nil{return nil,err}
 complete:=release
 owned,err=outbound.ContextForRuntimeOwnedSession(owned,b.source)
 if err!=nil{complete();return nil,err}
 raw,err:=next(owned)
 if raw==nil{complete();return nil,err}
 wrapped,fence:=outbound.WrapRuntimeOwnedConn(raw)
 registerErr:=creation.Register(fence)
 b.holdCarrier(fence,complete)
 if err!=nil||registerErr!=nil||b.physical.ctx.Err()!=nil{return nil,errors.Join(err,registerErr,b.physical.ctx.Err(),fence.RuntimeCloseAndWait())}
 return wrapped,nil
}

func(b *runtimeEndpointBinding)listenPacket(ctx context.Context,destination M.Socksaddr)(net.PacketConn,error){
 creation,err:=b.physical.carriers.Begin();if err!=nil{return nil,err};defer creation.Done()
 owned,release,err:=b.acquire(ctx);if err!=nil{return nil,err}
 complete:=release
 owned,err=outbound.ContextForRuntimeOwnedSession(owned,b.source)
 if err!=nil{complete();return nil,err}
 raw,err:=b.dialer.ListenPacket(owned,destination)
 if raw==nil{complete();return nil,err}
 wrapped,fence:=outbound.WrapRuntimeOwnedPacketConn(raw)
 registerErr:=creation.Register(fence)
 b.holdCarrier(fence,complete)
 if err!=nil||registerErr!=nil||b.physical.ctx.Err()!=nil{return nil,errors.Join(err,registerErr,b.physical.ctx.Err(),fence.RuntimeCloseAndWait())}
 return wrapped,nil
}
