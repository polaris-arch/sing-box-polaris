package http

import (
 "context"
 "net"
 stdhttp "net/http"
 "net/http/httptest"
 "testing"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/internal/runtimegraph"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)

type heldRuntimeHTTPHandler struct{entered,finish chan struct{}}
func(h *heldRuntimeHTTPHandler)NewConnectionEx(_ context.Context,conn net.Conn,_,_ M.Socksaddr,onClose N.CloseHandlerFunc){
 close(h.entered);<-h.finish;_ = conn.Close();onClose(nil)
}
func(*heldRuntimeHTTPHandler)NewPacketConnectionEx(context.Context,N.PacketConn,M.Socksaddr,M.Socksaddr,N.CloseHandlerFunc){panic("unexpected packet fixture")}

func TestRuntimeHTTPUpstreamInvocationRetainsBeforeScheduling(t *testing.T){
 closed:=make(chan struct{})
 owner,err:=runtimegraph.NewResourceOwner(context.Background(),adapter.RuntimeResourceID{Incarnation:"server",Sequence:1},nil,func()error{close(closed);return nil});if err!=nil{t.Fatal(err)}
 lease,err:=owner.Acquire();if err!=nil{t.Fatal(err)}
 ctx:=adapter.ContextWithRuntimeResourceLease(context.Background(),lease)
 handler:=&heldRuntimeHTTPHandler{entered:make(chan struct{}),finish:make(chan struct{})}
 conn:=newUpstreamConn(ctx,handler,M.Socksaddr{},M.Socksaddr{})
 waitHTTPBarrier(t,handler.entered)
 lease.Release();owner.Seal()
 assertHTTPPending(t,closed)
 close(handler.finish);waitHTTPBarrier(t,conn.done);waitHTTPBarrier(t,closed)
 _ = conn.Close()
}
func TestRuntimeHTTPRejectsLateHandlerBeforeTouchingRetiredServer(t *testing.T){
 owner,err:=runtimegraph.NewResourceOwner(context.Background(),adapter.RuntimeResourceID{Incarnation:"server",Sequence:2},nil,func()error{return nil});if err!=nil{t.Fatal(err)}
 lease,err:=owner.Acquire();if err!=nil{t.Fatal(err)}
 ctx:=adapter.ContextWithRuntimeResourceLease(context.Background(),lease);lease.Release();owner.Seal()
 request:=httptest.NewRequest(stdhttp.MethodGet,"http://example.test/",nil).WithContext(ctx)
 response:=httptest.NewRecorder()
 // A nil retired server makes any access before ownership admission observable.
 (&httpHandler{}).ServeHTTP(response,request)
 if response.Code!=stdhttp.StatusServiceUnavailable{t.Fatal("stale handler admitted")}
}
