package listener

import (
 "context"
 "errors"
 "net/netip"
 "sync"
 "testing"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/internal/runtimegraph"
 M "github.com/sagernet/sing/common/metadata"
)

type packetControlFixture struct{entered,release chan struct{};once sync.Once;panicCall bool}
func(c *packetControlFixture)ConsumeRuntimeControlPacket(context.Context,[]byte,M.Socksaddr)bool{
 if c.panicCall{panic("control callback")};if c.entered!=nil{c.once.Do(func(){close(c.entered)});<-c.release};return false
}
func(c *packetControlFixture)AuthorizeRuntimeControlWrite([]byte,M.Socksaddr)bool{return false}
func privateControlListener(t *testing.T,control RuntimePacketControl)*Listener{
 t.Helper();id:=adapter.RuntimeResourceID{Incarnation:"control",Sequence:1}
 owner,err:=runtimegraph.NewResourceOwner(context.Background(),id,nil,func()error{return nil});if err!=nil{t.Fatal(err)}
 l:=&Listener{ctx:adapter.ContextWithRuntimeResourceSource(context.Background(),owner)}
 l.runtime=&runtimeListener{phase:"inert",gateway:NewAdmissionGateway(nil,owner),closeDone:make(chan struct{}),runStop:make(chan struct{})}
 if err:=l.BindRuntimePacketControl(control);err!=nil{t.Fatal(err)}
 l.runtime.phase="armed"
 t.Cleanup(func(){_ = l.RuntimeCloseAndWait();owner.Seal()})
 return l
}
func TestPrivatePacketControlNeverOpensPublicAdmission(t *testing.T){
 l:=privateControlListener(t,&packetControlFixture{})
 if err:=l.BeginRuntimePacketControl();err!=nil{t.Fatal(err)}
 if !l.runtimeWaitPacketIngress(){t.Fatal("private UDP worker did not wake")}
 if _,_,err:=l.runtime.gateway.Acquire(context.Background());!errors.Is(err,ErrAdmissionPaused){t.Fatal("private phase opened user admission")}
 if !l.dispatchRuntimeControl([]byte("unmatched"),M.ParseSocksaddr("127.0.0.1:123")){t.Fatal("unmatched private packet escaped to user route")}
 endpoint:=&RuntimePacketTransport{listener:l}
 if _,err:=endpoint.WriteRuntimeControlTo(l.ctx,[]byte("unapproved"),M.ParseSocksaddr("127.0.0.1:123"));err==nil{t.Fatal("unapproved control packet reached socket")}
 if err:=l.EndRuntimePacketControl();err!=nil{t.Fatal(err)}
}
func TestPrivatePacketControlEndJoinsActualCallback(t *testing.T){
 control:=&packetControlFixture{entered:make(chan struct{}),release:make(chan struct{})};l:=privateControlListener(t,control)
 if err:=l.BeginRuntimePacketControl();err!=nil{t.Fatal(err)}
 callbackDone:=make(chan struct{});endDone:=make(chan struct{})
 var release sync.Once;open:=func(){release.Do(func(){close(control.release)})}
 t.Cleanup(func(){open();<-callbackDone;<-endDone})
 go func(){l.dispatchRuntimeControl(nil,M.Socksaddr{});close(callbackDone)}()
 // Start End independently so cleanup always has both terminal channels.
 go func(){<-control.entered;_ = l.EndRuntimePacketControl();close(endDone)}()
 waitFixture(t,control.entered)
 // Exact ending state is guarded; observing its changed signal avoids sleeps.
 l.runtime.mu.Lock();ending:=l.runtime.controlEnding;l.runtime.gateway.mu.Lock();changed:=l.runtime.gateway.changed;l.runtime.gateway.mu.Unlock();l.runtime.mu.Unlock()
 if !ending{waitFixture(t,changed)}
 pendingFixture(t,endDone)
 if err:=l.BeginRuntimePacketControl();err==nil{t.Fatal("reopened control while callback draining")}
 open();waitFixture(t,callbackDone);waitFixture(t,endDone)
}
func TestPrivatePacketControlPanicIsStickyCleanupUncertainty(t *testing.T){
 l:=privateControlListener(t,&packetControlFixture{panicCall:true})
 if err:=l.BeginRuntimePacketControl();err!=nil{t.Fatal(err)}
 if !l.dispatchRuntimeControl(nil,M.Socksaddr{}){t.Fatal("panic packet escaped private phase")}
 if err:=l.EndRuntimePacketControl();err==nil{t.Fatal("panic reported completed cleanup")}
 if err:=l.RuntimeCloseAndWait();err==nil{t.Fatal("panic uncertainty disappeared at close")}
}
func TestRuntimePacketReplyRejectsMissingListenerContinuation(t *testing.T){
 l:=privateControlListener(t,&packetControlFixture{})
 if _,err:=l.WriteRuntimePacketContext(context.Background(),nil,nil,netip.MustParseAddrPort("127.0.0.1:123"));err==nil{t.Fatal("unowned reply accepted")}
}
