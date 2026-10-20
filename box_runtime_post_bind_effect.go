package box

import (
 "context"
 "errors"
 "fmt"
 "strings"

 "github.com/sagernet/sing-box/adapter"
)

type runtimePostBindRecord struct{effect adapter.RuntimePostBindEffect;keys []string}
func runtimeEffectCall(name string,call func()error)(err error){
 defer func(){if recover()!=nil{err=fmt.Errorf("%s panicked; effect completion unknown",name)}}()
 return call()
}

// Validate the complete candidate occupancy before suspending any old control
// worker. Removed registrations also suspend here, while their socket is live.
func(s *Box)prepareRuntimePostBindEffects(ctx context.Context,g *preparedRuntimeGraph)error{
 occupied:=make(map[string]bool)
 next:=make(map[*runtimeResource]bool,len(g.resources))
 created:=make(map[*runtimeResource]bool,len(g.created));for _,r:=range g.created{created[r]=true}
 for _,r:=range g.resources{
  next[r]=true
  for _,entry:=range r.postBindEffects{
   for _,key:=range entry.keys{if key=="udp-mapping-port:*"{continue};if occupied[key]{return errors.New("candidate post-bind effects conflict")};occupied[key]=true}
   if created[r]{g.postBindNext=append(g.postBindNext,entry)}
  }
 }
 s.runtime.access.Lock();old:=append([]*runtimeResource(nil),s.runtime.resources...);s.runtime.access.Unlock()
 for _,r:=range old{if !next[r]{g.postBindPrevious=append(g.postBindPrevious,r.postBindEffects...)}}
 for _,entry:=range g.postBindPrevious{
  if err:=ctx.Err();err!=nil{return err}
  err:=runtimeEffectCall("old control suspension",func()error{return entry.effect.SuspendRuntime(ctx)})
  if err!=nil{g.postBindError=errors.Join(g.postBindError,err);return err}
  g.postBindSuspended=append(g.postBindSuspended,entry)
 }
 return nil
}
func(g *preparedRuntimeGraph)stageRuntimePostBindEffects(ctx context.Context)error{
 // Port-zero identities become exact only after physical bind. No external
 // registration is attempted until the complete bound candidate is unique.
 occupied:=make(map[string]bool)
 for _,resource:=range g.resources{for _,entry:=range resource.postBindEffects{
  keys:=entry.keys
  if bound,ok:=entry.effect.(interface{RuntimeBoundConflictKeys()([]string,error)});ok{
   var err error;keys,err=bound.RuntimeBoundConflictKeys();if err!=nil{return err}
  }
  if len(keys)==0{return errors.New("bound external effect has no conflict identity")}
  for _,key:=range keys{if key==""||strings.HasSuffix(key,":*")||occupied[key]{return errors.New("bound candidate external effects conflict or remain unresolved")};occupied[key]=true}
 }}
 for _,entry:=range g.postBindNext{
  if err:=ctx.Err();err!=nil{return err}
  g.postBindStaged=append(g.postBindStaged,entry)
  if entry.effect.RuntimeExternalEffects(){g.externalEffectsAttempted=true}
  if err:=runtimeEffectCall("candidate control staging",func()error{return entry.effect.StageRuntime(ctx)});err!=nil{return err}
 }
 return nil
}
// Cleanup has independent lifetime. Request cancellation cannot certify remote
// deregistration or permit conflicting re-registration. The external observer
// can time out while the owned compensation retains its evidence.
func(g *preparedRuntimeGraph)suspendRuntimeCandidateEffects()bool{
 absent:=true
 for i:=len(g.postBindStaged)-1;i>=0;i--{
  entry:=g.postBindStaged[i]
  err:=runtimeEffectCall("candidate control suspension",func()error{return entry.effect.SuspendRuntime(context.Background())})
  if err!=nil{absent=false;g.postBindError=errors.Join(g.postBindError,err)}
 }
 return absent
}
func(g *preparedRuntimeGraph)restoreRuntimePreviousEffects(){
 for i:=len(g.postBindSuspended)-1;i>=0;i--{
  entry:=g.postBindSuspended[i]
  err:=runtimeEffectCall("old control restoration",func()error{return entry.effect.RestoreRuntime(context.Background())})
  if err!=nil{g.postBindError=errors.Join(g.postBindError,err)}
 }
}
func(s *Box)recordRuntimePostBindEffects(record *runtimePlanRecord,g *preparedRuntimeGraph){
 if g==nil||g.postBindError==nil{return}
 s.runtime.access.Lock();defer s.runtime.access.Unlock()
 record.operation.Errors=append(record.operation.Errors,RuntimePlanError{Code:"CONTROL_EFFECT_RESTORATION_UNKNOWN",Path:"inbounds",Message:"candidate unpublished; external registration or local control restoration remains unconfirmed"})
}
