package shadowtls

import (
 "context"
 "errors"
 "net"
 "testing"
 "time"

 M "github.com/sagernet/sing/common/metadata"
)

type handshakeDialFixture struct { calls int; conn *handshakeConnFixture }
func(d *handshakeDialFixture)DialContext(context.Context,string,M.Socksaddr)(net.Conn,error){d.calls++;return d.conn,nil}
func(*handshakeDialFixture)ListenPacket(context.Context,M.Socksaddr)(net.PacketConn,error){return nil,net.ErrClosed}
type handshakeConnFixture struct{ closes int; closeErr error }
func(*handshakeConnFixture)Read([]byte)(int,error){return 0,net.ErrClosed}
func(*handshakeConnFixture)Write(p []byte)(int,error){return len(p),nil}
func(c *handshakeConnFixture)Close()error{c.closes++;return c.closeErr}
func(*handshakeConnFixture)LocalAddr()net.Addr{return &net.TCPAddr{}}
func(*handshakeConnFixture)RemoteAddr()net.Addr{return &net.TCPAddr{}}
func(*handshakeConnFixture)SetDeadline(time.Time)error{return nil}
func(*handshakeConnFixture)SetReadDeadline(time.Time)error{return nil}
func(*handshakeConnFixture)SetWriteDeadline(time.Time)error{return nil}
func TestRuntimeShadowTLSHandshakeCarrierOwnsExactIncomingGraph(t *testing.T){
 for _,failure:=range []bool{false,true}{
  f:=newIngressFixture();ctx,graph:=f.context()
  raw:=&handshakeConnFixture{};if failure{raw.closeErr=errors.New("close result uncertain")}
  base:=&handshakeDialFixture{conn:raw};dialer:=&runtimeHandshakeDialer{Dialer:base}
  if _,err:=dialer.DialContext(ctx,"tcp",M.Socksaddr{});err==nil||base.calls!=0{t.Fatal("unowned handshake dial admitted")}
  carriers:=&runtimeHandshakeCarriers{};ctx=context.WithValue(ctx,runtimeHandshakeKey{},carriers)
  if _,err:=dialer.DialContext(ctx,"tcp",M.Socksaddr{});err!=nil{t.Fatal(err)}
  graph.Release()
  if f.graphs.Load()!=1{t.Fatal("physical handshake did not retain graph")}
  err:=carriers.close()
  if failure {if err==nil||f.graphs.Load()!=1{t.Fatal("uncertain physical close falsely released graph")}} else if err!=nil||f.graphs.Load()!=0{t.Fatal("physical handshake close leaked graph")}
  if raw.closes!=1{t.Fatal("handshake carrier closed more than once")}
 }
}
