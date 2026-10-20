//go:build windows

package directorywindows

import (
 "context"
 "runtime/debug"

 "github.com/sagernet/sing-box/adapter"
 C "github.com/sagernet/sing-box/constant"
 "github.com/sagernet/sing-box/option"
)

// PreparePhysicalChildActivation creates a new original authority for a runtime
// physical child. Full captured configuration, source provenance and original
// binding are validated before inherited activation/mapping values are shadowed.
// It neither acquires a directory lease nor reuses an earlier activation token.
func PreparePhysicalChildActivation(ctx context.Context,options option.Options,poisonRoot func(string)error)(context.Context,error){
 info,_:=debug.ReadBuildInfo()
 if _,err:=validateWindowsActivationOptions(ctx,options,C.SourceRevision,info);err!=nil{return nil,err}
 ctx=adapter.ContextWithTailscaleDirectoryDomain(ctx,nil)
 ctx=adapter.ContextWithTailscaleDirectoryMapping(ctx,nil)
 ctx=context.WithValue(ctx,preparedActivationKey{},(*PreparedActivation)(nil))
 prepared,err:=PrepareActivation(ctx,options,poisonRoot);if err!=nil{return nil,err}
 // Consume exactly this new token against the same complete projection.
 return Prepare(prepared,options,poisonRoot)
}
