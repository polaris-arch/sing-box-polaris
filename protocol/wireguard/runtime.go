package wireguard

import (
 "context"
 "errors"
 "net"
 "slices"
 "sync"
 "sync/atomic"
 "syscall"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/endpoint"
 "github.com/sagernet/sing-box/adapter/outbound"
 "github.com/sagernet/sing-box/common/dialer"
 "github.com/sagernet/sing-box/common/tls"
 "github.com/sagernet/sing-box/option"
 "github.com/sagernet/sing/common"
 "github.com/sagernet/sing/common/control"
 "github.com/sagernet/sing/common/bufio"
 "github.com/sagernet/wireguard-go/device"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)

type runtimePhysicalEndpointKey struct{}
type runtimeEndpointPhysical struct {
 child *Endpoint
 ctx context.Context
 scope *adapter.Scope
 callbacks *outbound.RuntimeIOFence
 carriers *outbound.RuntimeIOFenceSet
 begin func(context.Context)(context.Context,func(),error)
 source adapter.RuntimeResourceSource
 cancel context.CancelFunc
 gate atomic.Bool
 ingress atomic.Bool
 once sync.Once
 done chan struct{}
 err error
}
func(p *runtimeEndpointPhysical)close()error{
 p.once.Do(func(){
  p.err=tls.NewRuntimeCleanupError(errors.New("WireGuard physical close did not complete"))
  defer close(p.done)
  p.gate.Store(false);p.ingress.Store(false);p.cancel();_ = p.callbacks.Close();p.carriers.Stop()
  p.err=errors.Join(p.scope.Close(),p.callbacks.Wait(),p.carriers.Wait())
  if p.err!=nil{p.err=tls.NewRuntimeCleanupError(p.err)}
 });<-p.done;return p.err
}
type runtimeEndpointOperation struct{done chan struct{};err error}
type runtimeEndpointState struct{
 mu sync.Mutex
 source adapter.RuntimeResourceSource
 options option.WireGuardEndpointOptions
 physical *runtimeEndpointPhysical
 operation *runtimeEndpointOperation
 openPhysical func(*runtimeEndpointPhysical)error
 closing bool
 closeOnce sync.Once
 closeDone chan struct{}
 closeErr error
}
func(w *Endpoint)initializeRuntime(options option.WireGuardEndpointOptions)error{
 if _,ok:=any((*device.Device)(nil)).(interface{ RuntimeEndpointCompletion() });!ok{return errors.New("WireGuard native endpoint completion adapter is not selected")}
 if options.System{return errors.New("WireGuard system device requires restart")}
 source,ok:=adapter.RuntimeResourceSourceFromContext(w.ctx);if !ok{return errors.New("WireGuard runtime owner missing")}
 r:=&runtimeEndpointState{source:source,options:cloneRuntimeOptions(options),closeDone:make(chan struct{})}
 w.runtime=r;r.openPhysical=w.openRuntimePhysical
 return adapter.DeferConstructionCleanup(w.ctx,w.RuntimeCloseAndWait)
}
func(w *Endpoint)RuntimeValidate()error{if w.runtime==nil{return errors.New("WireGuard has no private physical lifecycle")};return nil}
func(w *Endpoint)RuntimeResourceID()adapter.RuntimeResourceID{if w.runtime==nil{return adapter.RuntimeResourceID{}};return w.runtime.source.ID()}
func(w *Endpoint)PrepareRuntime(adapter.StartStage,*adapter.Scope)error{return w.RuntimeValidate()}
// WireGuard reserves no native custody slots. This common transaction boundary
// remains inert and checks that an existing owner has not begun terminal close.
func(w *Endpoint)RuntimeReservePhysical(context.Context)error{if err:=w.RuntimeValidate();err!=nil{return err};w.runtime.mu.Lock();defer w.runtime.mu.Unlock();if w.runtime.closing{return net.ErrClosed};return nil}
func(w *Endpoint)RuntimeReleasePhysicalReservation(context.Context)error{return w.RuntimeValidate()}
func(w *Endpoint)RuntimeStop(){if w.runtime==nil{return};w.runtime.mu.Lock();p:=w.runtime.physical;w.runtime.mu.Unlock();if p!=nil{p.ingress.Store(false)}}
func(w *Endpoint)RuntimeCloseAndWait()error{
 r:=w.runtime;if r==nil{return errors.New("WireGuard runtime owner missing")}
 r.closeOnce.Do(func(){
  r.mu.Lock();r.closing=true;operation:=r.operation;r.mu.Unlock()
  r.closeErr=tls.NewRuntimeCleanupError(errors.New("WireGuard logical close did not complete"));defer close(r.closeDone)
  if operation!=nil{<-operation.done}
  r.mu.Lock();p:=r.physical;r.mu.Unlock();r.closeErr=nil
  if p!=nil{r.closeErr=p.close()}
  if operation!=nil&&tls.IsRuntimeCleanupIncomplete(operation.err){r.closeErr=tls.NewRuntimeCleanupError(errors.Join(r.closeErr,operation.err))}
 });<-r.closeDone;return r.closeErr
}
func(r *runtimeEndpointState)run(ctx context.Context,fn func()error)error{
 r.mu.Lock();if r.closing{r.mu.Unlock();return net.ErrClosed}
 if previous:=r.operation;previous!=nil{select{case <-previous.done:default:r.mu.Unlock();return errors.New("WireGuard physical operation still running")}}
 op:=&runtimeEndpointOperation{done:make(chan struct{})};r.operation=op;r.mu.Unlock()
 go func(){
  op.err=tls.NewRuntimeCleanupError(errors.New("WireGuard physical operation did not return"))
  defer func(){if recover()!=nil{op.err=tls.NewRuntimeCleanupError(errors.New("WireGuard physical operation panicked; owner retained"))};close(op.done)}()
  op.err=fn()
 }()
 select{case <-op.done:return op.err;case <-ctx.Done():return ctx.Err()}
}
func(w *Endpoint)RuntimeStagePhysical(ctx context.Context)error{
 if err:=w.RuntimeValidate();err!=nil{return err};r:=w.runtime
 return r.run(ctx,func()error{
  r.mu.Lock();existing:=r.physical;r.mu.Unlock()
  if existing!=nil{select{case <-existing.done:if existing.err!=nil{return existing.err};default:return errors.New("WireGuard physical child already exists")}}
  physicalContext,cancel:=context.WithCancel(w.ctx);callbacks:=outbound.NewRuntimeIOFence(nil)
  scope:=adapter.NewScope(physicalContext,outbound.WrapRuntimeLogger(w.logger,callbacks))
  p:=&runtimeEndpointPhysical{scope:scope,callbacks:callbacks,carriers:outbound.NewRuntimeIOFenceSet(),source:r.source,cancel:cancel,done:make(chan struct{})}
  p.ctx=adapter.ContextWithConstructionScope(context.WithValue(scope.Context(),runtimePhysicalEndpointKey{},p),scope)
  // Keep the failed child before any device constructor, resolver or socket.
  r.mu.Lock();r.physical=p;r.mu.Unlock()
  var err error;p.begin,err=outbound.RegisterRuntimeOwnedFence(p.ctx,callbacks);if err!=nil{return errors.Join(err,p.close())}
  if err=r.openPhysical(p);err!=nil{return errors.Join(err,p.close())};return nil
 })
}
func(w *Endpoint)RuntimeSuspendPhysical(ctx context.Context)error{
 if err:=w.RuntimeValidate();err!=nil{return err}
 return w.runtime.run(ctx,func()error{w.runtime.mu.Lock();p:=w.runtime.physical;w.runtime.mu.Unlock();if p==nil{return nil};return p.close()})
}
func(w *Endpoint)openRuntimePhysical(p *runtimeEndpointPhysical)error{
 raw,err:=NewEndpoint(p.ctx,w.router,outbound.WrapRuntimeLogger(w.logger,p.callbacks),w.Tag(),w.runtime.options)
 if err!=nil{return err};p.child=raw.(*Endpoint)
 for _,stage:=range adapter.ListStartStages{if err=p.scope.Start("WireGuard physical child",p.child,stage);err!=nil{return err}}
 return nil
}
func(w *Endpoint)runtimeChild()(*Endpoint,func(),error){
 r:=w.runtime;r.mu.Lock();p:=r.physical;r.mu.Unlock()
 if p==nil||!p.gate.Load(){return nil,nil,net.ErrClosed}
 leave,err:=p.callbacks.Acquire();if err!=nil{return nil,nil,err}
 if !p.gate.Load(){leave();return nil,nil,net.ErrClosed};return p.child,leave,nil
}
type RuntimeEndpointPublication struct{physical []*runtimeEndpointPhysical}
func PrepareRuntimeEndpointPublication(endpoints []*Endpoint)(*RuntimeEndpointPublication,error){
 result:=&RuntimeEndpointPublication{}
 for _,w:=range endpoints{
  if err:=w.RuntimeValidate();err!=nil{return nil,err};r:=w.runtime;r.mu.Lock();p,op,closing:=r.physical,r.operation,r.closing;r.mu.Unlock()
  if closing||p==nil||op==nil{return nil,errors.New("WireGuard child preparation incomplete")}
  select{case <-op.done:if op.err!=nil{return nil,op.err};default:return nil,errors.New("WireGuard child preparation running")}
  select{case <-p.done:return nil,net.ErrClosed;default:};result.physical=append(result.physical,p)
 };return result,nil
}
func(p *RuntimeEndpointPublication)Publish(){for _,child:=range p.physical{child.gate.Store(true);child.ingress.Store(true)}}

// The standard UDP listener capability is preserved without an Upstream escape.
// Native WireGuard owns and joins its standard sockets; graph-facing Control
// callbacks are fenced, including bind-update workers that outlive Device.Close.
func(p *runtimeEndpointPhysical)wrapDialer(base N.Dialer)N.Dialer{
 d:=&runtimeEndpointDialer{physical:p,base:base}
 if listener,ok:=common.Cast[dialer.UDPListener](base);ok{return &runtimeEndpointUDPListener{runtimeEndpointDialer:d,listener:listener}}
 return d
}
type runtimeEndpointDialer struct{physical *runtimeEndpointPhysical;base N.Dialer}
func(d *runtimeEndpointDialer)DialContext(ctx context.Context,network string,destination M.Socksaddr)(net.Conn,error){
 p:=d.physical;creation,err:=p.carriers.Begin();if err!=nil{return nil,err};defer creation.Done()
 ctx,finish:=p.creationContext(ctx);defer finish()
 ctx,release,err:=p.begin(ctx);if err!=nil{return nil,err};defer release()
 ctx,err=outbound.ContextForRuntimeOwnedSession(ctx,p.source);if err!=nil{return nil,err}
 raw,err:=d.base.DialContext(ctx,network,destination)
 if raw==nil{return nil,err};wrapped,fence:=outbound.WrapRuntimeOwnedConn(raw)
 registerErr:=creation.Register(fence)
 if err!=nil||registerErr!=nil||p.ctx.Err()!=nil{return nil,errors.Join(err,registerErr,p.ctx.Err(),fence.RuntimeCloseAndWait())};return wrapped,nil
}
func(d *runtimeEndpointDialer)ListenPacket(ctx context.Context,destination M.Socksaddr)(net.PacketConn,error){
 p:=d.physical;creation,err:=p.carriers.Begin();if err!=nil{return nil,err};defer creation.Done()
 ctx,finish:=p.creationContext(ctx);defer finish()
 ctx,release,err:=p.begin(ctx);if err!=nil{return nil,err};defer release()
 ctx,err=outbound.ContextForRuntimeOwnedSession(ctx,p.source);if err!=nil{return nil,err}
 raw,err:=d.base.ListenPacket(ctx,destination)
 if raw==nil{return nil,err};wrapped,fence:=outbound.WrapRuntimeOwnedPacketConn(raw)
 registerErr:=creation.Register(fence)
 if err!=nil||registerErr!=nil||p.ctx.Err()!=nil{return nil,errors.Join(err,registerErr,p.ctx.Err(),fence.RuntimeCloseAndWait())};return wrapped,nil
}
type runtimeEndpointUDPListener struct{*runtimeEndpointDialer;listener dialer.UDPListener}
func(d *runtimeEndpointUDPListener)UDPListenerControl()(control.Func,bool){
 callback,egress:=d.listener.UDPListenerControl()
 return func(network,address string,raw syscall.RawConn)error{
  leave,err:=d.physical.callbacks.Acquire();if err!=nil{return err};defer leave()
  if callback==nil{return nil};return callback(network,address,raw)
 },egress
}
func cloneRuntimePointer[T any](value *T)*T{if value==nil{return nil};copy:=*value;return &copy}
func cloneRuntimeOptions(value option.WireGuardEndpointOptions)option.WireGuardEndpointOptions{
 value.Address=slices.Clone(value.Address);value.Peers=slices.Clone(value.Peers)
 for index:=range value.Peers{peer:=&value.Peers[index];peer.AllowedIPs=slices.Clone(peer.AllowedIPs);peer.Reserved=slices.Clone(peer.Reserved)}
 value.Inet4BindAddress=cloneRuntimePointer(value.Inet4BindAddress);value.Inet6BindAddress=cloneRuntimePointer(value.Inet6BindAddress)
 value.UDPFragment=cloneRuntimePointer(value.UDPFragment);value.NetworkStrategy=cloneRuntimePointer(value.NetworkStrategy)
 value.NetworkType=slices.Clone(value.NetworkType);value.FallbackNetworkType=slices.Clone(value.FallbackNetworkType)
 value.DomainResolver=cloneRuntimePointer(value.DomainResolver)
 if resolver:=value.DomainResolver;resolver!=nil{resolver.Policy=cloneRuntimePointer(resolver.Policy);resolver.RewriteTTL=cloneRuntimePointer(resolver.RewriteTTL);resolver.ClientSubnet=cloneRuntimePointer(resolver.ClientSubnet)}
 return value
}
var _ endpoint.RuntimePreparedEndpoint=(*Endpoint)(nil)

// RuntimePhysicalIdentity is immutable constructor metadata for collision checks.
func(w *Endpoint)RuntimePhysicalIdentity()(system bool,name string,port uint16){
 if w.runtime==nil{return true,"",0};o:=w.runtime.options;return o.System,o.Name,o.ListenPort
}
// Preserve the caller's values/deadline and additionally cancel when this exact
// physical child stops. Completion joins the actual cancellation callback.
func(p *runtimeEndpointPhysical)creationContext(ctx context.Context)(context.Context,func()){
 ctx,cancel:=context.WithCancel(ctx);done:=make(chan struct{})
 stop:=context.AfterFunc(p.ctx,func(){defer close(done);cancel()})
 return ctx,func(){cancel();if !stop(){<-done}}
}

// Native inbound flows retain their physical owner separately from the current
// routing graph. The callback fence alone ends when routing returns and cannot
// cover the lifetime of a TCP stream or UDP association.
type runtimeInboundHandshake struct{
 physical any
 ctx context.Context
 fence *outbound.RuntimeIOFence
 readHandshake bool
 writeHandshake bool
}
func(h *runtimeInboundHandshake)call(callback func()error)error{
 _,release,err:=adapter.AcquireRuntimeOperation(h.ctx,nil);if err!=nil{return err};defer release()
 leave,err:=h.fence.Acquire();if err!=nil{return err};defer leave();return callback()
}
func(h *runtimeInboundHandshake)HandshakeSuccess()error{return h.call(func()error{if value,ok:=h.physical.(interface{HandshakeSuccess()error});ok{return value.HandshakeSuccess()};return nil})}
func(h *runtimeInboundHandshake)HandshakeFailure(err error)error{return h.call(func()error{if value,ok:=h.physical.(interface{HandshakeFailure(error)error});ok{return value.HandshakeFailure(err)};return nil})}
func(h *runtimeInboundHandshake)NeedHandshakeForRead()bool{return h.readHandshake}
func(h *runtimeInboundHandshake)NeedHandshakeForWrite()bool{return h.writeHandshake}
func runtimeHandshake(physical any,ctx context.Context,fence *outbound.RuntimeIOFence)*runtimeInboundHandshake{
 h:=&runtimeInboundHandshake{physical:physical,ctx:ctx,fence:fence}
 if value,ok:=physical.(interface{NeedHandshakeForRead()bool});ok{h.readHandshake=value.NeedHandshakeForRead()}
 if value,ok:=physical.(interface{NeedHandshakeForWrite()bool});ok{h.writeHandshake=value.NeedHandshakeForWrite()}
 return h
}
type runtimeInboundConn struct{net.Conn;*runtimeInboundHandshake}
type runtimeInboundPacket struct{N.PacketConn;*runtimeInboundHandshake}
func(p *runtimeEndpointPhysical)wrapInboundConn(ctx context.Context,conn net.Conn,onClose N.CloseHandlerFunc)(context.Context,net.Conn,N.CloseHandlerFunc,error){
 owned,release,err:=adapter.AcquireRuntimeOperation(ctx,p.source);if err!=nil{return ctx,conn,onClose,err}
 physical,fence:=outbound.WrapRuntimeOwnedConn(conn)
 wrapped:=&runtimeInboundConn{Conn:outbound.WrapRuntimeConn(owned,release,physical),runtimeInboundHandshake:runtimeHandshake(conn,owned,fence)}
 return owned,wrapped,N.OnceClose(func(err error){_ = wrapped.Close();if onClose!=nil{onClose(err)}}),nil
}
func(p *runtimeEndpointPhysical)wrapInboundPacket(ctx context.Context,conn N.PacketConn,onClose N.CloseHandlerFunc)(context.Context,N.PacketConn,N.CloseHandlerFunc,error){
 owned,release,err:=adapter.AcquireRuntimeOperation(ctx,p.source);if err!=nil{return ctx,conn,onClose,err}
 physical,fence:=outbound.WrapRuntimeOwnedPacketConn(bufio.NewNetPacketConn(conn))
 wrapped:=&runtimeInboundPacket{PacketConn:bufio.NewPacketConn(outbound.WrapRuntimePacketConn(owned,release,physical)),runtimeInboundHandshake:runtimeHandshake(conn,owned,fence)}
 return owned,wrapped,N.OnceClose(func(err error){_ = wrapped.Close();if onClose!=nil{onClose(err)}}),nil
}
