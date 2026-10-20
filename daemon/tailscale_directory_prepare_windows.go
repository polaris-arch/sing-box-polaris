//go:build windows && with_tailscale

package daemon

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/directorywindows"
	"github.com/sagernet/sing-box/protocol/tailscale"
	"github.com/sagernet/sing/service"
)

func (s *StartedService) prepareManagedDirectories(request context.Context, p *preparedInstance) error {
 if p.runtimeGraph { return s.prepareRuntimeDirectoryEnvelope(request,p) }
	if p.options.PolarisWindowsDirectory == nil {
		if adapter.TailscaleDirectoryDomainFromContext(p.ctx) != nil || adapter.TailscaleDirectoryMappingFromContext(p.ctx) != nil {
			return errors.New("inherited managed Windows authority requires a prepared activation envelope")
		}
		return nil
	}
	if err := request.Err(); err != nil { return err }
	run,err := newTailscaleRetirementRun(p.profileContent,p.options)
	if err != nil { return err }
	ctx := service.ContextWithPtr(p.ctx,&run.binding)
	ctx,err = directorywindows.PrepareActivation(ctx,p.options,tailscale.PoisonDirectoryDomain)
	if err != nil { return err }
	ctx,cancel := context.WithCancel(ctx)
	plan,err := tailscale.NewPreparedDirectoryLeases(ctx,p.options)
	if err != nil { cancel(); return err }
	p.directoryFinished = make(chan struct{})
	run.closeFinished = p.directoryFinished
	run.installPreparedDirectories(plan,adapter.TailscaleDirectoryDomainFromContext(ctx))
	// Admission was checked by the lifecycle caller before this phase. Append
	// the actual original run before the first lease acquisition.
	if err=s.appendTailscaleRetirementRun(run);err!=nil{cancel();return err}
	p.ctx,p.directoryPlan,p.directoryRun,p.directoryCancel = plan.Context(),plan,run,cancel
	p.directoryWatch = watchDirectoryPreparation(request,cancel)
	acquired := false
	defer func() { if !acquired { _ = p.abortDirectories() } }()
	if err := plan.Acquire(request); err != nil { return err }
	acquired = true
	return nil
}

// Runtime endpoints acquire their own physical-child leases later. The outer
// Box has an explicitly empty original census and only validates its complete
// activation envelope here; it never consumes a whole-config child lease plan.
func(s *StartedService)prepareRuntimeDirectoryEnvelope(request context.Context,p *preparedInstance)error{
 if err:=request.Err();err!=nil{return err}
 if p.options.PolarisWindowsDirectory==nil{
  if adapter.TailscaleDirectoryDomainFromContext(p.ctx)!=nil||adapter.TailscaleDirectoryMappingFromContext(p.ctx)!=nil{return errors.New("inherited managed Windows authority requires a runtime activation envelope")}
  return directorywindows.RejectReservedPaths(p.options.RawMessage)
 }
 original:=p.options;original.Endpoints=nil
 run,err:=newTailscaleRetirementRun(p.profileContent,original);if err!=nil{return err}
 ctx:=service.ContextWithPtr(p.ctx,&run.binding)
 ctx,err=directorywindows.PrepareActivation(ctx,p.options,tailscale.PoisonDirectoryDomain);if err!=nil{return err}
 ctx,cancel:=context.WithCancel(ctx)
 finished:=make(chan struct{});run.closeFinished=finished
 run.directoryAuthority=adapter.TailscaleDirectoryDomainFromContext(ctx);run.directoryAuthorityBound=true
 if err=s.appendTailscaleRetirementRun(run);err!=nil{cancel();return err}
 p.ctx,p.directoryRun,p.directoryCancel,p.directoryFinished=ctx,run,cancel,finished
 return nil
}
