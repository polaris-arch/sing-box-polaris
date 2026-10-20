package box

import "github.com/sagernet/sing-box/option"

// This inventory follows constructor captures, not merely generic service tags.
// Returned HTTP definitions enter the receiving manager fingerprint as well as
// the service edge, since anonymous clients are manager-owned allocations.
func runtimeServiceDependencies(value any)(dependencies []string,clients []option.HTTPClientOptions,privateInbounds []string){
 dial:=func(options option.DialerOptions,domain bool){
  if options.Detour!=""{dependencies=append(dependencies,"outbound:"+options.Detour)}
  if domain&&(options.Detour==""||options.DomainResolver!=nil){dependencies=append(dependencies,"dns-router");if options.DomainResolver!=nil&&options.DomainResolver.Server!=""{dependencies=append(dependencies,"dns-transport:"+options.DomainResolver.Server)}}
 }
 switch options:=value.(type){
 case *option.ResolvedServiceOptions:dependencies=append(dependencies,"dns-router")
 case *option.SSMAPIServiceOptions:
  if options.Servers!=nil{for _,entry:=range options.Servers.Entries(){dependencies=append(dependencies,"inbound:"+entry.Value);privateInbounds=append(privateInbounds,"inbound:"+entry.Value)}}
 case *option.CCMServiceOptions:
  dependencies=append(dependencies,"dns-router")
  if options.Detour!=""{dependencies=append(dependencies,"outbound:"+options.Detour)}
 case *option.OCMServiceOptions:
  dependencies=append(dependencies,"dns-router")
  if options.Detour!=""{dependencies=append(dependencies,"outbound:"+options.Detour)}
 case *option.APIServiceOptions:
  if options.Dashboard!=nil&&options.Dashboard.Enabled{
   dependencies=append(dependencies,"http-manager")
   if options.Dashboard.HTTPClient!=nil{if options.Dashboard.HTTPClient.Tag==""{clients=append(clients,*options.Dashboard.HTTPClient)}}else{clients=append(clients,option.HTTPClientOptions{})}
  }
 case *option.DERPServiceOptions:
  for _,tag:=range options.VerifyClientEndpoint{dependencies=append(dependencies,"endpoint:"+tag)}
  for _,tag:=range options.VerifyClientInbound{dependencies=append(dependencies,"inbound:"+tag)}
  for _,verify:=range options.VerifyClientURL{if verify!=nil{dependencies=append(dependencies,"http-manager");if verify.HTTPClientOptions.Tag==""{clients=append(clients,verify.HTTPClientOptions)}}}
  for _,mesh:=range options.MeshWith{if mesh!=nil{dial(mesh.DialerOptions,mesh.ServerIsDomain())}}
 case *option.USBIPClientServiceOptions:dial(options.DialerOptions,options.ServerIsDomain())
 }
 return
}
