package vless

import (
 "bytes"
 "io"
 "net"
 "testing"
 "time"

 "github.com/sagernet/sing/common/buf"
 M "github.com/sagernet/sing/common/metadata"
)

type responseFixture struct { written bytes.Buffer; input *bytes.Reader; maxWrite int }
func(c *responseFixture)Read(p []byte)(int,error){if c.input==nil{return 0,io.EOF};return c.input.Read(p)}
func(c *responseFixture)Write(p []byte)(int,error){if c.maxWrite>0&&len(p)>c.maxWrite{p=p[:c.maxWrite]};return c.written.Write(p)}
func(*responseFixture)Close()error{return nil}
func(*responseFixture)LocalAddr()net.Addr{return &net.TCPAddr{}}
func(*responseFixture)RemoteAddr()net.Addr{return &net.TCPAddr{}}
func(*responseFixture)SetDeadline(time.Time)error{return nil}
func(*responseFixture)SetReadDeadline(time.Time)error{return nil}
func(*responseFixture)SetWriteDeadline(time.Time)error{return nil}
func TestRuntimeVLESSResponseWritesHeaderOnceAcrossShortWrites(t *testing.T){
 raw:=&responseFixture{maxWrite:1};response:=&runtimeVLESSResponseConn{Conn:raw}
 if _,err:=response.Write([]byte{7});err!=nil{t.Fatal(err)}
 if _,err:=response.Write([]byte{8});err!=nil{t.Fatal(err)}
 if !bytes.Equal(raw.written.Bytes(),[]byte{0,0,7,8}){t.Fatal("response header framing changed")}
 if _,ok:=any(response).(interface{Upstream()any});ok{t.Fatal("response leaked private TLS carrier")}
}
func TestRuntimeVLESSPacketFramingPreservesDestination(t *testing.T){
 destination:=M.ParseSocksaddr("example.com:53")
 raw:=&responseFixture{maxWrite:1,input:bytes.NewReader([]byte{0,2,4,5})}
 packet:=&runtimeVLESSPacketConn{runtimeVLESSResponseConn:&runtimeVLESSResponseConn{Conn:raw},destination:destination}
 buffer:=buf.NewSize(2);defer buffer.Release()
 actual,err:=packet.ReadPacket(buffer);if err!=nil{t.Fatal(err)}
 if actual!=destination||!bytes.Equal(buffer.Bytes(),[]byte{4,5}){t.Fatal("UDP request framing changed")}
 output:=buf.NewSize(2);_,_ = output.Write([]byte{6,7})
 if err:=packet.WritePacket(output,destination);err!=nil{t.Fatal(err)}
 if !bytes.Equal(raw.written.Bytes(),[]byte{0,0,0,2,6,7}){t.Fatal("UDP response framing changed")}
}
