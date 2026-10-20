//go:build with_tailscale

package tailscale

import (
 "context"
 "errors"
 "net"
 "sync/atomic"
 "testing"
 "time"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/outbound"
 M "github.com/sagernet/sing/common/metadata"
)

func TestTailcatTerminalJoinDoesNotHoldLazyMutex(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background())
 scope:=adapter.NewScope(ctx,nil)
 s:=&runtimeTailcatSession{ctx:ctx,cancel:cancel,scope:scope,callbacks:outbound.NewRuntimeIOFence(nil),carriers:outbound.NewRuntimeIOFenceSet()}
 // The sentinel node is never entered: this fixture owns only the exact
 // callback whose completion needs the lazy-owner mutex.
 o:=&TailcatOutbound{nodeContext:ctx,nodeCancel:cancel,node:&tailcatNode{},session:s}
 leave,err:=s.callbacks.Acquire();if err!=nil{t.Fatal(err)}
 returned:=make(chan struct{})
 go func(){<-ctx.Done();o.access.Lock();o.access.Unlock();leave();close(returned)}()
 if err=o.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
 <-returned
 if _,_,err=o.acquire(context.Background());!errors.Is(err,net.ErrClosed){t.Fatalf("terminal owner admitted a new node: %v",err)}
}

type runtimeTailcatTestConn struct{
 entered chan struct{}
 returnRead chan struct{}
 closeEntered chan struct{}
}
func(c *runtimeTailcatTestConn)Read([]byte)(int,error){close(c.entered);<-c.returnRead;return 0,net.ErrClosed}
func(c *runtimeTailcatTestConn)Write(p []byte)(int,error){return len(p),nil}
func(c *runtimeTailcatTestConn)Close()error{close(c.closeEntered);return nil}
func(c *runtimeTailcatTestConn)LocalAddr()net.Addr{return &net.TCPAddr{}}
func(c *runtimeTailcatTestConn)RemoteAddr()net.Addr{return &net.TCPAddr{}}
func(c *runtimeTailcatTestConn)SetDeadline(time.Time)error{return nil}
func(c *runtimeTailcatTestConn)SetReadDeadline(time.Time)error{return nil}
func(c *runtimeTailcatTestConn)SetWriteDeadline(time.Time)error{return nil}
func TestTailcatPublicCarrierPinsNodeUntilOriginalMethodReturn(t *testing.T){
 ctx:=adapter.ContextWithRuntimeResourceSource(context.Background(),&runtimeBindingTestSource{sequence:10})
 o:=&TailcatOutbound{ctx:ctx}
 raw:=&runtimeTailcatTestConn{entered:make(chan struct{}),returnRead:make(chan struct{}),closeEntered:make(chan struct{})}
 var releases atomic.Int32;released:=make(chan struct{})
 conn:=o.ownRuntimeConn(raw,func(){releases.Add(1);close(released)})
 readDone:=make(chan struct{});go func(){_,_=conn.Read(make([]byte,1));close(readDone)}();<-raw.entered
 closeDone:=make(chan struct{});go func(){if err:=conn.Close();err!=nil{t.Error(err)};close(closeDone)}();<-raw.closeEntered
 if releases.Load()!=0{t.Fatal("lazy node released before original carrier method returned")}
 close(raw.returnRead);<-readDone;<-released;<-closeDone
 if releases.Load()!=1{t.Fatal("carrier released node more than once")}
}

func TestTailcatPublicEntriesAdmitExactResourceBeforeWork(t *testing.T){
 source:=&runtimeBindingTestSource{sequence:20}
 // All other fields are deliberately absent. A denied exact resource must
 // stop before logger, DNS, DERP map fetch or native lazy construction.
 o:=&TailcatOutbound{runtimeSource:source}
 if _,err:=o.DialContext(context.Background(),"tcp",M.Socksaddr{});err==nil{t.Fatal("dial ignored denied resource")}
 if source.roots.Load()!=1{t.Fatal("dial bypassed exact resource admission")}
 if _,_,err:=o.ListenPacketWithDestination(context.Background(),M.Socksaddr{});err==nil{t.Fatal("packet listen ignored denied resource")}
 if source.roots.Load()!=2{t.Fatal("packet entry bypassed exact resource admission")}
 o.InterfaceUpdated(context.Background())
 if source.roots.Load()!=3{t.Fatal("network notification bypassed exact resource admission")}
}
