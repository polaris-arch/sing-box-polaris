package tls

import (
 "context"
 "crypto/tls"
 "errors"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/certificate"
 "github.com/sagernet/sing-box/log"
 "github.com/sagernet/sing-box/option"
 "github.com/sagernet/sing/service"
)

// Named references borrow the exact provider allocation. Inline providers share
// the TLS consumer resource and its dependency closure, and own their lifecycle.
type runtimeManagedCertificate struct {
 reference *certificate.RuntimeReference
 owned certificate.RuntimePreparedProvider
 scope *adapter.Scope
}
func(p *runtimeManagedCertificate)Start()error{
 if p.owned==nil{return nil}
 for _,stage:=range adapter.ListStartStages{if err:=p.owned.PrepareRuntime(stage,p.scope);err!=nil{return err}}
 return nil
}
func(p *runtimeManagedCertificate)Close()error{if p.owned!=nil{return p.owned.RuntimeCloseAndWait()};return nil}
func(p *runtimeManagedCertificate)GetCertificate(hello *tls.ClientHelloInfo)(*tls.Certificate,error){return p.reference.GetCertificate(hello)}
func(p *runtimeManagedCertificate)GetACMENextProtos()[]string{return p.reference.GetACMENextProtos()}
func(p *runtimeManagedCertificate)RuntimeValidate()error{if p.reference==nil{return errors.New("unbound runtime certificate provider")};return nil}

func newRuntimeCertificateProvider(ctx context.Context,logger log.ContextLogger,options *option.CertificateProviderOptions)(managedCertificateProvider,error){
 var provider adapter.CertificateProviderService
 var owned certificate.RuntimePreparedProvider
 if options.IsShared(){
  manager:=service.FromContext[adapter.CertificateProviderManager](ctx)
  if manager==nil{return nil,errors.New("missing runtime certificate provider manager")}
  var found bool
  provider,found=manager.Get(options.Tag)
  if !found{return nil,errors.New("runtime certificate provider reference was not constructed")}
 }else{
  registry:=service.FromContext[adapter.CertificateProviderRegistry](ctx)
  if registry==nil{return nil,errors.New("missing runtime certificate provider registry")}
  var err error
  provider,err=registry.Create(ctx,logger,"",options.Type,options.Options);if err!=nil{return nil,err}
  var ok bool
  owned,ok=provider.(certificate.RuntimePreparedProvider)
  if !ok{return nil,errors.New("inline certificate provider has no staged lifecycle")}
 }
 reference,err:=certificate.BindRuntimeProvider(ctx,provider);if err!=nil{return nil,err}
 result:=&runtimeManagedCertificate{reference:reference,owned:owned}
 if owned!=nil{
  result.scope=adapter.NewScope(ctx,logger)
  if err:=adapter.DeferConstructionCleanup(ctx,result.scope.Close);err!=nil{return nil,err}
  if err:=adapter.ConstructionScopeErr(ctx);err!=nil{return nil,err}
  if err:=adapter.RegisterRuntimeEffect(ctx,owned);err!=nil{return nil,err}
 }
 return result,nil
}
