package listener

import (
 "context"
 "errors"
 "net"
 "os"
 "testing"
 "time"

 "github.com/sagernet/sing/common/buf"
 M "github.com/sagernet/sing/common/metadata"
)
func packetTransportFixture()*RuntimePacketTransport{return &RuntimePacketTransport{queue:make(chan runtimeDatagram,64),closed:make(chan struct{}),changed:make(chan struct{})}}
func TestPrivatePacketTransportPreservesPacketBoundary(t *testing.T){
 endpoint:=packetTransportFixture();defer endpoint.Close()
 packet:=buf.NewSize(3);_,_=packet.Write([]byte{1,2,3})
 endpoint.NewPacketContext(context.Background(),packet,M.ParseSocksaddr("127.0.0.1:1234"))
 data:=make([]byte,8);n,address,err:=endpoint.ReadFrom(data)
 if err!=nil||n!=3||address.String()!="127.0.0.1:1234"||data[2]!=3{t.Fatal("datagram identity or boundary changed")}
}
func TestPrivatePacketDeadlineAndCloseWakeReader(t *testing.T){
 endpoint:=packetTransportFixture()
 if err:=endpoint.SetReadDeadline(time.Unix(1,0));err!=nil{t.Fatal(err)}
 if _,_,err:=endpoint.ReadFrom(nil);!errors.Is(err,os.ErrDeadlineExceeded){t.Fatal("expired deadline ignored")}
 if err:=endpoint.SetReadDeadline(time.Time{});err!=nil{t.Fatal(err)}
 done:=make(chan error,1);go func(){_,_,err:=endpoint.ReadFrom(nil);done<-err}()
 if err:=endpoint.Close();err!=nil{t.Fatal(err)}
 if err:=<-done;!errors.Is(err,net.ErrClosed){t.Fatal("reader survived close")}
 if err:=endpoint.Close();err!=nil{t.Fatal(err)}
}
