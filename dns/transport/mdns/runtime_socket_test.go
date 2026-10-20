package mdns

import (
 "context"
 "errors"
 "net"
 "testing"
 "time"

 "github.com/sagernet/sing-box/log"
 mDNS "github.com/miekg/dns"
)

type failingPacketClose struct { net.PacketConn; calls int }
func (c *failingPacketClose) Close()error{c.calls++;return errors.New("packet close failed")}
func (c *failingPacketClose) WriteTo([]byte,net.Addr)(int,error){return 0,errors.New("write failed")}
func TestMDNSNormalReturnRetainsCloseFailure(t *testing.T){
 native:=new(failingPacketClose)
 original:=listenTargetPacket
 listenTargetPacket=func(*Transport,context.Context,queryTarget)(net.PacketConn,net.Addr,error){return native,&net.UDPAddr{},nil}
 t.Cleanup(func(){listenTargetPacket=original})
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 transport:=&Transport{operationCtx:ctx,operationCancel:cancel,logger:log.NewNOPFactory().Logger()}
 _,_=transport.exchangeTarget(ctx,queryTarget{},nil,mDNS.Question{},time.Now())
 if native.calls!=1 || transport.close()==nil {t.Fatal("normal return lost socket close failure")}
}
func TestMDNSFailedSetupRetainsCompensationFailure(t *testing.T){
 _,cancel:=context.WithCancel(context.Background());defer cancel()
 transport:=&Transport{operationCancel:cancel};native:=new(failingPacketClose)
 transport.closeSetupPacket(native)
 if native.calls!=1 || transport.close()==nil {t.Fatal("setup compensation was certified")}
}
func TestMDNSCancellationAndReturnCloseOnlyOnce(t *testing.T){
 native:=new(failingPacketClose);var retained packetSocketErrors
 conn:=&ownedPacketConn{PacketConn:native,errors:&retained}
 ctx,cancel:=context.WithCancel(context.Background());done:=make(chan struct{})
 context.AfterFunc(ctx,func(){defer close(done);_ = conn.Close()})
 cancel();<-done
 if conn.Close()==nil || native.calls!=1 || retained.result()==nil {t.Fatal("cancellation result lost")}
}
