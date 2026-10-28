package qtls

import (
 "context"
 "errors"
 "testing"
 "time"
 "github.com/sagernet/quic-go"
 aTLS "github.com/sagernet/sing/common/tls"
)
type runtimeConfigFixture struct {
 aTLS.ServerConfig
 context func(context.Context,*quic.Conn)(context.Context,error)
 task func(context.Context,func(context.Context))bool
}
func(f *runtimeConfigFixture)RuntimeServerContext(ctx context.Context,c *quic.Conn)(context.Context,error){return f.context(ctx,c)}
func(f *runtimeConfigFixture)RuntimeServerTask(ctx context.Context,task func(context.Context))bool{return f.task(ctx,task)}
func TestServerRuntimeLegacyContextIsUnchanged(t *testing.T){
 ctx:=context.WithValue(context.Background(),struct{}{},"legacy")
 actual,err:=ServerConnectionContext(nil,ctx,nil)
 if err!=nil||actual!=ctx{t.Fatal("legacy context changed")}
 done:=make(chan context.Context,1)
 if !RunServerTask(nil,ctx,func(c context.Context){done<-c}){t.Fatal("legacy launch rejected")}
 select{case got:=<-done:if got!=ctx{t.Fatal("legacy context changed")};case <-time.After(5*time.Second):t.Fatal("legacy launch watchdog")}
}
func TestServerRuntimeRejectsBeforeTaskLaunch(t *testing.T){
 fixture:=&runtimeConfigFixture{task:func(context.Context,func(context.Context))bool{return false}}
 if RunServerTask(fixture,context.Background(),func(context.Context){t.Fatal("rejected task invoked")}){t.Fatal("rejected task accepted")}
}
func TestServerRuntimeSuppliesOwnedTaskContext(t *testing.T){
 borrowed:=context.Background();owned:=context.WithValue(borrowed,struct{}{},"owned")
 fixture:=&runtimeConfigFixture{task:func(ctx context.Context,task func(context.Context))bool{
  if ctx!=borrowed{t.Fatal("input context replaced before admission")};task(owned);return true
 }}
 called:=false
 if !RunServerTask(fixture,borrowed,func(ctx context.Context){called=true;if ctx!=owned{t.Fatal("task lost acquired context")}})||!called{t.Fatal("task was not invoked")}
}
func TestServerRuntimeContextFailureIsPropagated(t *testing.T){
 sentinel:=errors.New("connection context unavailable")
 fixture:=&runtimeConfigFixture{context:func(context.Context,*quic.Conn)(context.Context,error){return nil,sentinel}}
 if ctx,err:=ServerConnectionContext(fixture,context.Background(),nil);ctx!=nil||!errors.Is(err,sentinel){t.Fatal(ctx,err)}
}
