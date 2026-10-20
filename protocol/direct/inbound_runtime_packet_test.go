package direct

import (
 "context"
 "net"
 "testing"
 "time"

 "github.com/sagernet/sing-box/common/listener"
 "github.com/sagernet/sing-box/log"
 "github.com/sagernet/sing/common/buf"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)

type ingressPacketFixture struct { closed bool }
func (*ingressPacketFixture) ReadPacket(*buf.Buffer)(M.Socksaddr,error){return M.Socksaddr{},net.ErrClosed}
func (*ingressPacketFixture) WritePacket(buffer *buf.Buffer,_ M.Socksaddr)error{buffer.Release();return nil}
func(c *ingressPacketFixture)Close()error{c.closed=true;return nil}
func(*ingressPacketFixture)LocalAddr()net.Addr{return &net.UDPAddr{}}
func(*ingressPacketFixture)SetDeadline(time.Time)error{return nil}
func(*ingressPacketFixture)SetReadDeadline(time.Time)error{return nil}
func(*ingressPacketFixture)SetWriteDeadline(time.Time)error{return nil}
var _ N.PacketConn = (*ingressPacketFixture)(nil)

func TestRuntimeDirectPacketOwnsLaunchAndCarrierSeparately(t *testing.T){
 f:=newIngressFixture();construction,scope:=ingressConstruction(f);defer scope.Close()
 state,err:=newInboundRuntime(construction,func()error{return nil});if err!=nil{t.Fatal(err)}
 h:=&Inbound{runtime:state,listener:listener.New(listener.Options{Context:construction,Logger:log.NewNOPFactory().Logger()})}
 packet,graph:=f.context()
 ok,callback,_,_:=h.prepareRuntimePacketConnection(M.Socksaddr{},packet)
 if !ok{t.Fatal("actual prelaunch prepare refused")}
 graph.Release()
 prepared:=callback.Value(runtimePacketKey{}).(*runtimePacketInvocation)
 raw:=&ingressPacketFixture{};carrier:=prepared.wrap(raw)
 // The launch reservation ends with the handler invocation, never the carrier.
 prepared.releaseInvocation()
 if f.graphs.Load()==0||f.resources.Load()==0{t.Fatal("asynchronous carrier lost exact ownership")}
 if err:=carrier.Close();err!=nil{t.Fatal(err)}
 if !raw.closed||f.graphs.Load()!=0||f.resources.Load()!=0{t.Fatal("carrier terminal close did not release its ownership")}
 if ok,_,_,_:=h.prepareRuntimePacketConnection(M.Socksaddr{},context.Background());ok{t.Fatal("packet without incoming graph admitted")}
}
