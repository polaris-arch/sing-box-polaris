package listener

import (
 "context"
 "errors"
 "net"
 "net/netip"

 "github.com/sagernet/sing-box/adapter"
 M "github.com/sagernet/sing/common/metadata"
)

// Payload is borrowed only for the call. Implementations authenticate the exact
// pending peer/transaction before copying into their owned bounded control inbox.
// No public session or current-graph lookup is permitted on this private path.
type RuntimePacketControl interface{
 ConsumeRuntimeControlPacket(context.Context,[]byte,M.Socksaddr)bool
 AuthorizeRuntimeControlWrite([]byte,M.Socksaddr)bool
}
func(l *Listener)BindRuntimePacketControl(control RuntimePacketControl)error{
 if l.runtime==nil||control==nil{return ErrRuntimeRawTransport}
 r:=l.runtime;r.mu.Lock();defer r.mu.Unlock()
 if r.phase!="inert"||r.control!=nil{return ErrRuntimeTransition};r.control=control;return nil
}
func(l *Listener)BeginRuntimePacketControl()error{
 if l.runtime==nil{return ErrRuntimeRawTransport};r:=l.runtime
 r.mu.Lock();defer r.mu.Unlock();r.gateway.mu.Lock();defer r.gateway.mu.Unlock()
 if r.phase!="armed"||r.controlEnding||r.control==nil||r.gateway.open||r.gateway.sealed{return ErrRuntimeTransition}
 if !r.controlOpen{r.controlOpen=true;close(r.gateway.changed);r.gateway.changed=make(chan struct{})};return nil
}
func(l *Listener)EndRuntimePacketControl()error{
 if l.runtime==nil{return ErrRuntimeRawTransport};r:=l.runtime
 r.mu.Lock();r.gateway.mu.Lock()
 if r.controlEnding{r.gateway.mu.Unlock();r.mu.Unlock();return ErrRuntimeTransition}
 r.controlEnding=true;r.controlOpen=false;close(r.gateway.changed);r.gateway.changed=make(chan struct{})
 r.gateway.mu.Unlock();r.mu.Unlock()
 r.controlCalls.Wait()
 r.mu.Lock();r.controlEnding=false;err:=r.controlError;r.mu.Unlock();return err
}
func(l *Listener)runtimeWaitPacketIngress()bool{
 if l.runtime==nil{return true};r:=l.runtime
 for{
  r.mu.Lock();r.gateway.mu.Lock()
  open:=r.gateway.open||r.controlOpen;sealed:=r.gateway.sealed;changed:=r.gateway.changed;stop:=r.runStop
  r.gateway.mu.Unlock();r.mu.Unlock()
  if sealed{return false};if open{select{case <-stop:return false;default:return true}}
  select{case <-stop:return false;case <-changed:}
 }
}
func(l *Listener)dispatchRuntimeControl(payload []byte,source M.Socksaddr)(private bool){
 r:=l.runtime;r.mu.Lock()
 if !r.controlOpen||r.phase!="armed"{r.mu.Unlock();return false}
 handler:=r.control;r.controlCalls.Add(1);r.mu.Unlock();defer r.controlCalls.Done()
 // Every packet in this phase remains private, even classification failures.
 private=true
 ctx,release,err:=adapter.AcquireRuntimeOperation(l.ctx,r.gateway.source);if err!=nil{return true};defer release()
 defer func(){if recover()!=nil{r.mu.Lock();r.controlError=errors.New("candidate packet-control callback panicked; completion unknown");r.mu.Unlock()}}()
 _=handler.ConsumeRuntimeControlPacket(ctx,payload,source)
 return true
}

// WriteRuntimePacketContext reports the actual socket write, not queue admission.
// Existing admitted replies may finish while ingress is paused. No shared socket
// deadline is changed, and cancellation cannot claim an unfinished write ended.
func(l *Listener)WriteRuntimePacketContext(ctx context.Context,payload,oob []byte,destination netip.AddrPort)(int,error){
 if l.runtime==nil{return 0,ErrRuntimeRawTransport};r:=l.runtime
 if _,ok:=adapter.RuntimeResourceLeaseFromContext(ctx,r.gateway.source.ID());!ok{return 0,errors.New("UDP reply lacks exact listener continuation")}
 _,release,err:=adapter.AcquireRuntimeOperation(ctx,r.gateway.source);if err!=nil{return 0,err};defer release()
 return l.writeRuntimePacketBytes(ctx,payload,oob,destination)
}
func(l *Listener)writeRuntimePacketBytes(ctx context.Context,payload,oob []byte,destination netip.AddrPort)(int,error){
 if err:=ctx.Err();err!=nil{return 0,err}
 r:=l.runtime;r.mu.Lock()
 if l.shutdown.Load()||!r.ownsUDP||r.udpReleased||l.udpConn==nil||!r.outputStarted{r.mu.Unlock();return 0,net.ErrClosed}
 conn:=l.udpConn;r.directWrites.Add(1);r.mu.Unlock();defer r.directWrites.Done()
 n,_,err:=conn.WriteMsgUDPAddrPort(payload,oob,destination);return n,err
}
func(p *RuntimePacketTransport)WriteRuntimeControlTo(ctx context.Context,payload []byte,destination M.Socksaddr)(n int,err error){
 l:=p.listener;r:=l.runtime;r.mu.Lock()
 if !r.controlOpen||r.phase!="armed"||r.control==nil{r.mu.Unlock();return 0,ErrRuntimeTransition}
 control:=r.control;r.controlCalls.Add(1);r.mu.Unlock();defer r.controlCalls.Done()
 owned,release,err:=adapter.AcquireRuntimeOperation(ctx,r.gateway.source);if err!=nil{return 0,err};defer release()
 defer func(){if recover()!=nil{r.mu.Lock();r.controlError=errors.New("candidate control write panicked; completion unknown");err=r.controlError;r.mu.Unlock()}}()
 if !control.AuthorizeRuntimeControlWrite(payload,destination){return 0,errors.New("unauthorized candidate control datagram")}
 if !destination.IsIP(){return 0,errors.New("candidate control destination is unresolved")}
 return l.writeRuntimePacketBytes(owned,payload,nil,destination.AddrPort())
}
