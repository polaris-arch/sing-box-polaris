package naive
import (
 "testing"
 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/inbound"
 "github.com/sagernet/sing-box/log"
 "github.com/sagernet/sing-box/option"
 "github.com/sagernet/sing/common/auth"
)
func TestRuntimeNaiveConstructorAndPrepareRemainPrivate(t *testing.T){
 f:=newIngressFixture();ctx,scope:=ingressConstruction(f);defer scope.Close()
 options:=option.NaiveInboundOptions{Network:"tcp",Users:[]auth.User{{Username:"fixture",Password:"fixture"}}}
 member,err:=NewInbound(ctx,nil,log.NewNOPFactory().Logger(),"in",options);if err!=nil{t.Fatal(err)}
 prepared:=member.(inbound.RuntimePreparedInbound)
 for _,stage:=range []adapter.StartStage{adapter.StartStateInitialize,adapter.StartStateStart,adapter.StartStateStart}{if err:=prepared.PrepareRuntime(stage,scope);err!=nil{t.Fatal(err)}}
 for _,l:=range prepared.RuntimeListeners(){if l.RuntimeStatus().Phase!="inert"{t.Fatal("private preparation activated listener")}}
 if f.graphAcquires.Load()!=0||f.sourceAcquires.Load()!=0{t.Fatal("private preparation admitted a request")}
}
