package v2ray

import (
 "github.com/sagernet/sing-box/transport/runtimeingress"
 "errors"
 "net"
 "sync/atomic"
 "testing"
)

type runtimeServerCloseFixture struct{entered,release chan struct{};calls atomic.Int32}
func(s *runtimeServerCloseFixture)Network()[]string{return []string{"tcp"}}
func(s *runtimeServerCloseFixture)Serve(net.Listener)error{return nil}
func(s *runtimeServerCloseFixture)ServePacket(net.PacketConn)error{return nil}
func(s *runtimeServerCloseFixture)Close()error{s.calls.Add(1);close(s.entered);<-s.release;return nil}
func TestRuntimeServerCloseJoinsServeAndNativeClose(t *testing.T){
 native:=&runtimeServerCloseFixture{entered:make(chan struct{}),release:make(chan struct{})}
 serveDone:=make(chan struct{})
 server:=&runtimeServer{V2RayServerTransport:native,done:serveDone,closed:make(chan struct{})}
 closed:=make(chan error,1);go func(){closed<-server.Close()}();<-native.entered
 close(native.release)
 select{case <-closed:t.Fatal("Serve tail not joined");default:}
 close(serveDone);if err:=<-closed;err!=nil{t.Fatal(err)}
 if err:=server.Close();err!=nil{t.Fatal(err)}
 if native.calls.Load()!=1{t.Fatal("transport closed twice")}
}
func TestRuntimeServerUnknownServeOutcomeIsSticky(t *testing.T){
 native:=&runtimeServerCloseFixture{entered:make(chan struct{}),release:make(chan struct{})};close(native.release)
 server:=&runtimeServer{V2RayServerTransport:native,closed:make(chan struct{}),result:errors.New("injected worker uncertainty")}
 first:=server.Close();if first==nil{t.Fatal("unknown Serve outcome was discarded")}
 if server.Close()!=first{t.Fatal("cleanup outcome was not sticky")}
}
func TestRuntimeAcceptorSignalsReadyBeforeReceiving(t *testing.T){
 acceptor:=runtimeingress.NewStreamAcceptor()
 done:=make(chan error,1);go func(){_,err:=acceptor.Accept();done<-err}();<-acceptor.Ready()
 if err:=acceptor.Close();err!=nil{t.Fatal(err)}
 if err:=<-done;!errors.Is(err,net.ErrClosed){t.Fatal("closed private acceptor remained live")}
}
