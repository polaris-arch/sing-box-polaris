package udpnat

import (
 "context"
 "errors"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/sagernet/sing/common/buf"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)

type runtimeLineageKey struct{}
type runtimeAuthKey struct{}
type runtimeHandlerFixture struct {
 refs atomic.Int64
 retains atomic.Int64
 reject bool
 entered chan context.Context
 proceed chan struct{}
 errorEntered chan struct{}
 errorProceed chan struct{}
 released chan struct{}
}
func (h *runtimeHandlerFixture) RetainPacketContext(ctx context.Context) (func(context.Context)context.Context,func(),error) {
 if h.reject { return nil,nil,errors.New("admission closed") }
 lineage:=ctx.Value(runtimeLineageKey{})
 h.retains.Add(1);h.refs.Add(1)
 var once sync.Once
 return func(final context.Context)context.Context{return context.WithValue(final,runtimeLineageKey{},lineage)},func(){once.Do(func(){if h.refs.Add(-1)==0{select{case h.released<-struct{}{}:default:}}})},nil
}
func (h *runtimeHandlerFixture) NewPacketConnection(ctx context.Context,conn N.PacketConn,_ M.Metadata)error {
 h.entered<-ctx
 <-h.proceed
 for range 2 { packet:=buf.NewSize(1);_,err:=conn.ReadPacket(packet);packet.Release();if err!=nil{return err} }
 return errors.New("session terminal error")
}
func(h *runtimeHandlerFixture)NewError(context.Context,error){close(h.errorEntered);<-h.errorProceed}
type runtimeWriterFixture struct{}
func(runtimeWriterFixture)WritePacket(buffer *buf.Buffer,_ M.Socksaddr)error{buffer.Release();return nil}
func runtimePacketFixture()*buf.Buffer{p:=buf.NewSize(1);_ = p.WriteByte(1);return p}
func runtimeWaitFixture(t *testing.T,ch <-chan struct{}){t.Helper();select{case <-ch:case <-time.After(5*time.Second):t.Fatal("callback barrier watchdog")}}

func TestRuntimePacketContextRetainsBeforeLaunchAndJoinsTerminalTail(t *testing.T){
 h:=&runtimeHandlerFixture{entered:make(chan context.Context,1),proceed:make(chan struct{}),errorEntered:make(chan struct{}),errorProceed:make(chan struct{}),released:make(chan struct{},8)}
 service:=New[int](60,h)
 initial:=context.WithValue(context.Background(),runtimeLineageKey{},"first graph")
 initialize:=func(N.PacketConn)(context.Context,N.PacketWriter){return context.WithValue(context.Background(),runtimeAuthKey{},"relay user"),runtimeWriterFixture{}}
 service.NewContextPacketEx(initial,1,runtimePacketFixture(),M.Socksaddr{},M.Socksaddr{},initialize)
 var seen context.Context
 select{case seen=<-h.entered:case <-time.After(5*time.Second):t.Fatal("session not launched")}
 if seen.Value(runtimeLineageKey{})!="first graph"||seen.Value(runtimeAuthKey{})!="relay user"{t.Fatal("lineage or authenticated context lost")}
 next:=context.WithValue(context.Background(),runtimeLineageKey{},"later graph")
 service.NewContextPacketEx(next,1,runtimePacketFixture(),M.Socksaddr{},M.Socksaddr{},initialize)
 if h.retains.Load()!=2||h.refs.Load()!=1{t.Fatal("loaded packet changed retained association")}
 select{case <-h.entered:t.Fatal("loaded session relaunched");default:}
 close(h.proceed);runtimeWaitFixture(t,h.errorEntered)
 if h.refs.Load()!=1{t.Fatal("error callback tail lost ownership")}
 close(h.errorProceed);runtimeWaitFixture(t,h.released)
 if h.refs.Load()!=0{t.Fatal("terminal ownership leaked")}
}
func TestRuntimePacketContextFailureDoesNotPublishSession(t *testing.T){
 h:=&runtimeHandlerFixture{reject:true,entered:make(chan context.Context,1),proceed:make(chan struct{}),errorEntered:make(chan struct{}),errorProceed:make(chan struct{}),released:make(chan struct{},8)}
 service:=New[int](60,h)
 calls:=0
 initialize:=func(N.PacketConn)(context.Context,N.PacketWriter){calls++;return context.Background(),runtimeWriterFixture{}}
 service.NewContextPacketEx(context.Background(),1,runtimePacketFixture(),M.Socksaddr{},M.Socksaddr{},initialize)
 if calls!=0||h.refs.Load()!=0{t.Fatal("failed admission published an unowned cache entry")}
 select{case <-h.entered:t.Fatal("failed admission launched a callback");default:}
}
