package tuic

import (
 "context"
 "testing"
 "github.com/sagernet/quic-go"
 "github.com/sagernet/sing/common/buf"
 aTLS "github.com/sagernet/sing/common/tls"
)
type rejectedRuntimeConfig struct{aTLS.ServerConfig;calls int}
func(c *rejectedRuntimeConfig)RuntimeServerContext(ctx context.Context,_ *quic.Conn)(context.Context,error){return ctx,nil}
func(c *rejectedRuntimeConfig)RuntimeServerTask(context.Context,func(context.Context))bool{c.calls++;return false}
func TestRejectedRuntimePacketSessionClosesAndRemovesExactEntry(t *testing.T){
 config:=new(rejectedRuntimeConfig)
 session:=&serverSession[int]{Service:&Service[int]{tlsConfig:config},ctx:context.Background(),udpConnMap:make(map[uint16]*udpPacketConn)}
 message:=allocMessage();message.sessionID=7;message.data=buf.NewSize(1);message.data.WriteByte(1)
 session.handleUDPMessage(message,false)
 if config.calls!=1{t.Fatal("new session did not attempt prelaunch acquisition")}
 if len(session.udpConnMap)!=0{t.Fatal("failed acquisition left private session published")}
 // A nil physical QUIC connection is intentional: neither RemoteAddr nor the
 // graph-facing handler may execute after denied prelaunch acquisition.
}
