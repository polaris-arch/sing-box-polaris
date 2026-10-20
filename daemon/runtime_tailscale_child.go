package daemon

import (
 "context"
 "errors"
 "os"
 "sync"

 "github.com/sagernet/sing-box/adapter"
 C "github.com/sagernet/sing-box/constant"
 "github.com/sagernet/sing-box/option"
 "github.com/sagernet/sing/service"
)

type runtimeChildDirectoryPlan interface{
 preparedDirectoryResources
 Acquire(context.Context)error
}
type runtimeTailscaleChild struct{
 op sync.Mutex // lifecycle operation serialization, never used by context/snapshot callbacks
 mu sync.Mutex
 ctx context.Context
 run *tailscaleRetirementRun
 request adapter.RuntimeTailscaleChildRequest
 options option.Options
 selected option.Endpoint
 plan runtimeChildDirectoryPlan
 entered,committed,aborted bool
 abortErr error
}
func(s *StartedService)registerRuntimeTailscaleChild(ctx context.Context,request adapter.RuntimeTailscaleChildRequest)(adapter.RuntimeTailscaleChildRegistration,error){
 canonical,ok:=adapter.RuntimeTailscaleConfiguration(ctx);if !ok{return nil,errors.New("Tailscale child lacks captured whole configuration")}
 options,err:=parseConfig(ctx,string(canonical));if err!=nil{return nil,err}
 var selected option.Endpoint;found:=false
 for _,endpoint:=range options.Endpoints{
  if endpoint.Tag!=request.Tag{continue}
  if found||endpoint.Type!=C.TypeTailscale{return nil,errors.New("Tailscale physical child identity is ambiguous")}
  settings,ok:=endpoint.Options.(*option.TailscaleEndpointOptions)
  if !ok||os.ExpandEnv(settings.StateDirectory)!=request.StateDirectory||os.ExpandEnv(settings.TaildropDirectory)!=request.TaildropDirectory{return nil,errors.New("Tailscale physical child paths differ from captured configuration")}
  selected=endpoint;found=true
 }
 if !found{return nil,errors.New("Tailscale child is absent from captured configuration")}
 run,err:=newTailscaleRetirementRun(string(canonical),option.Options{Endpoints:[]option.Endpoint{selected}});if err!=nil{return nil,err}
 run.closeFinished=request.CloseDone
 child:=&runtimeTailscaleChild{run:run,request:request,options:options,selected:selected}
 physicalBase:=ctx
 if base,ok:=adapter.RuntimeTailscaleChildBase(ctx);ok{physicalBase=base}
 // Preserve original birth bytes while detaching the physical service context
 // from the first logical graph. ResourceID validation remains in the registrar.
 physicalBase=adapter.ContextWithRuntimeTailscaleConfiguration(physicalBase,canonical)
 child.ctx=service.ContextWithPtr(service.ExtendContext(physicalBase),&run.binding)
 // Register the immutable original birth before any mapping/lease acquisition.
 if err=s.appendTailscaleRetirementRun(run);err!=nil{return nil,err}
 go child.observeActualClose()
 return child,nil
}
func(c *runtimeTailscaleChild)Context()context.Context{c.mu.Lock();defer c.mu.Unlock();return c.ctx}
func(c *runtimeTailscaleChild)Prepare(request context.Context)error{
 c.op.Lock();defer c.op.Unlock()
 c.mu.Lock()
 if c.entered||c.aborted||c.committed{c.mu.Unlock();return errors.New("Tailscale physical preparation replay")}
 c.entered=true;c.mu.Unlock()
 // Lifecycle sequencing owns this method; cancellation never launches an
 // asynchronous plan Abort that could race its actual constructor binding.
 ctx,plan,err:=prepareRuntimeChildDirectories(c.ctx,c.options,c.selected)
 if err!=nil{return err}
 c.mu.Lock();c.ctx,c.plan=ctx,plan;c.mu.Unlock()
 c.run.access.Lock();c.run.directoryAuthority=adapter.TailscaleDirectoryDomainFromContext(ctx);c.run.directoryAuthorityBound=true;c.run.access.Unlock()
 if plan!=nil{c.run.installPreparedDirectories(plan,adapter.TailscaleDirectoryDomainFromContext(ctx));return plan.Acquire(request)}
 return request.Err()
}
func(c *runtimeTailscaleChild)Constructed()error{
 c.op.Lock();defer c.op.Unlock()
 select{case <-c.request.ConstructionDone:default:return errors.New("Tailscale constructor is not terminal")}
 if err:=c.request.ConstructionResult();err!=nil{return err}
 c.mu.Lock();invalid:=!c.entered||c.aborted||c.committed;c.mu.Unlock()
 if invalid{return errors.New("Tailscale construction commit replay")}
 if err:=c.ctx.Err();err!=nil{return err}
 if c.plan!=nil{
  if err:=c.run.transferPreparedDirectories(c.plan,c.request.DirectoryScopes);err!=nil{return err}
  if err:=c.plan.Validate(c.request.DirectoryScopes());err!=nil{return err}
  if err:=c.plan.Commit();err!=nil{return err}
 }else{c.run.captureDirectories(c.request.DirectoryScopes)}
 c.run.capture(c.request.StoreScopes());c.mu.Lock();c.committed=true;c.mu.Unlock();return nil
}
func(c *runtimeTailscaleChild)Abort()error{
 c.op.Lock();defer c.op.Unlock()
 c.mu.Lock()
 if c.committed{c.mu.Unlock();return nil}
 if c.aborted{err:=c.abortErr;c.mu.Unlock();return err}
 select{case <-c.request.ConstructionDone:default:c.mu.Unlock();return errors.New("Tailscale constructor still owns preparation")}
 c.aborted=true;plan:=c.plan;c.mu.Unlock()
 var err error
 if plan!=nil{err=plan.Abort()}
 c.mu.Lock();c.abortErr=err;c.mu.Unlock();return err
}
func(c *runtimeTailscaleChild)observeActualClose(){
 defer func(){if recover()!=nil{c.run.freeze(nil,false);c.run.freezeDirectories(nil,false)}}()
 <-c.request.CloseDone
 c.op.Lock();defer c.op.Unlock()
 // CloseDone alone cannot supply a missing constructor terminal observation.
 select{case <-c.request.ConstructionDone:default:return}
 constructionErr,closeErr:=c.request.ConstructionResult(),c.request.CloseResult()
 c.mu.Lock();entered,committed,abortErr:=c.entered,c.committed,c.abortErr;c.mu.Unlock()
 noAcquisition,marker:=constructionErr.(interface{RuntimeTailscaleNoAcquisition()bool})
 if !entered&&marker&&noAcquisition.RuntimeTailscaleNoAcquisition()&&closeErr==nil&&abortErr==nil{
  c.run.access.Lock()
  c.run.runtimeNoAcquisition=true;c.run.originalCloseSucceeded=true
  c.run.final=&tailscaleRetirementInstance{RunNonce:c.run.binding.RunNonce,ConfigDigest:c.run.binding.ConfigDigest,Terminal:"NoStoreConstruction",CensusComplete:true,Nodes:[]adapter.TailscaleStoreNode{}}
  c.run.directoryFinal=&tailscaleDirectoryInstance{RunNonce:c.run.binding.RunNonce,ConfigDigest:c.run.binding.ConfigDigest,Terminal:"NoDirectoryConstruction",CensusComplete:true,Nodes:[]adapter.TailscaleDirectoryNode{}}
  c.run.access.Unlock();return
 }
 c.run.freeze(c.request.StoreScopes(),committed&&constructionErr==nil&&closeErr==nil&&abortErr==nil)
 c.run.freezeDirectories(c.request.DirectoryScopes(),committed&&constructionErr==nil&&closeErr==nil&&abortErr==nil)
 c.run.access.Lock();c.run.originalCloseSucceeded=closeErr==nil&&abortErr==nil;c.run.access.Unlock()
}
