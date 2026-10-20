package tls

import (
 "context"
 "testing"
 "time"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/log"
)

func newRuntimeServerConfigFixture(t *testing.T)*STDServerConfig{
 t.Helper()
 scope:=adapter.NewScope(context.Background(),log.NewNOPFactory().Logger())
 ctx:=adapter.ContextWithRuntimePreparation(adapter.ContextWithConstructionScope(scope.Context(),scope))
 c:=&STDServerConfig{ctx:ctx,logger:log.NewNOPFactory().Logger()}
 if err:=c.initializeRuntimeServer();err!=nil{t.Fatal(err)}
 return c
}
func waitRuntimeServer(t *testing.T,done <-chan struct{}){t.Helper();select{case <-done:case <-time.After(5*time.Second):t.Fatal("server lifecycle watchdog")}}
func TestRuntimeServerCloseWaitsForActualStartUnwind(t *testing.T){
 c:=newRuntimeServerConfigFixture(t);entered,finish,returned:=make(chan struct{}),make(chan struct{}),make(chan struct{})
 go func(){defer close(returned);_ = c.runtime.start(func()error{close(entered);<-finish;return nil})}()
 waitRuntimeServer(t,entered)
 _ = c.runtime.fence.Close()
 done:=make(chan struct{});go func(){_ = c.Close();close(done)}()
 select{case <-done:t.Fatal("close overtook partial Start");default:}
 close(finish);waitRuntimeServer(t,returned);waitRuntimeServer(t,done)
 if err:=c.runtime.start(func()error{t.Error("late Start invoked");return nil});err==nil{t.Fatal("late Start admitted")}
}
func TestRuntimeServerCloseJoinsAdmittedWatcherCallback(t *testing.T){
 c:=newRuntimeServerConfigFixture(t)
 leave,err:=c.runtime.fence.Acquire();if err!=nil{t.Fatal(err)}
 _ = c.runtime.fence.Close()
 done:=make(chan struct{});go func(){_ = c.Close();close(done)}()
 select{case <-done:t.Fatal("watcher tail lost");default:}
 if _,err:=c.runtime.fence.Acquire();err==nil{t.Fatal("late callback admitted")}
 leave();waitRuntimeServer(t,done)
}
func TestRuntimeServerStartPanicRetainsUnknownCompletion(t *testing.T){
 c:=newRuntimeServerConfigFixture(t)
 func(){defer func(){_ = recover()}();_ = c.runtime.start(func()error{panic("partial provider initialization")})}()
 if err:=c.Close();err==nil{t.Fatal("panic incorrectly certified cleanup")}
}
