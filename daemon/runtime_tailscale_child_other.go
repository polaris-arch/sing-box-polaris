//go:build !windows || !with_tailscale

package daemon

import (
 "context"
 "github.com/sagernet/sing-box/option"
)
func prepareRuntimeChildDirectories(ctx context.Context,options option.Options,selected option.Endpoint)(context.Context,runtimeChildDirectoryPlan,error){
 // Unix managed directories retain the explicitly supplied host domain, but
 // each child gets a new mapping and its own immutable original run binding.
 prepared,err:=prepareTailscaleDirectoryMapping(ctx,option.Options{Endpoints:[]option.Endpoint{selected}})
 return prepared,nil,err
}
