package box

import (
 "context"
 "errors"

 "github.com/sagernet/sing-box/adapter"
 C "github.com/sagernet/sing-box/constant"
 protocolTun "github.com/sagernet/sing-box/protocol/tun"
)

func runtimeTunParticipants(resources []*runtimeResource)[]*protocolTun.Inbound{
 var result []*protocolTun.Inbound
 for _,resource:=range resources{for _,component:=range resource.components{if value,ok:=component.inbound.(*protocolTun.Inbound);ok{result=append(result,value)}}}
 return result
}
func(s *Box)stageRuntimeTun(ctx context.Context,g *preparedRuntimeGraph,allowReconnect bool)error{
 current:=make(map[*runtimeResource]bool,len(g.resources));for _,resource:=range g.resources{current[resource]=true}
 s.runtime.access.Lock();old:=append([]*runtimeResource(nil),s.runtime.resources...);s.runtime.access.Unlock()
 var replaced []*runtimeResource
 for _,resource:=range old{if !current[resource]{replaced=append(replaced,resource)}}
 previous,next:=runtimeTunParticipants(replaced),runtimeTunParticipants(g.created)
 if len(previous)==0&&len(next)==0{return nil}
 if len(previous)!=0&&!allowReconnect{return errors.New("TUN physical replacement requires accepted session-reset impact")}
 g.tunTransaction=protocolTun.NewRuntimeSetTransaction(previous,next)
 return g.tunTransaction.Stage(ctx)
}
func(g *preparedRuntimeGraph)restoreRuntimeTun(){
 if g.tunTransaction==nil{return}
 ctx,cancel:=context.WithTimeout(context.Background(),C.StopTimeout);defer cancel()
 g.tunRestorationError=g.tunTransaction.Compensate(ctx)
}

// Rule sets are captured only while constructing a physical resource. Packet
// admission still goes through the stable graph gateway, never a pinned router.
type runtimeInboundRouter struct{adapter.Router;rules map[string]adapter.RuleSet}
func(r *runtimeInboundRouter)RuleSet(tag string)(adapter.RuleSet,bool){value,ok:=r.rules[tag];return value,ok}

func(s *Box)recordRuntimeTunRestoration(record *runtimePlanRecord,g *preparedRuntimeGraph){
 if g==nil||g.tunTransaction==nil{return}
 s.runtime.access.Lock();defer s.runtime.access.Unlock()
 if g.tunRestorationError!=nil{record.operation.Errors=append(record.operation.Errors,RuntimePlanError{Code:"TUN_RESTORATION_INCOMPLETE",Path:"inbounds",Message:"candidate unpublished; previous TUN physical state could not be confirmed restored"})}
 if g.tunTransaction.AffectedSessionsReset(){record.operation.Errors=append(record.operation.Errors,RuntimePlanError{Code:"TUN_SESSIONS_RESET",Path:"inbounds",Message:"local TUN replacement interrupted affected sessions; restoration does not restore those sessions"})}
}
