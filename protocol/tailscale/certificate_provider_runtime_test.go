//go:build with_tailscale

package tailscale

import (
 "context"
 "crypto/tls"
 "errors"
 "strings"
 "testing"
 "time"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/outbound"
 "github.com/sagernet/sing-box/internal/runtimegraph"
)

type certificateEndpointFixture struct { id adapter.RuntimeResourceID; err error }
func(f certificateEndpointFixture)RuntimeResourceID()adapter.RuntimeResourceID{return f.id}
func(f certificateEndpointFixture)RuntimeValidate()error{return f.err}
func TestTailscaleCertificateRequiresConcreteEndpointLifecycle(t *testing.T){
 if _,err:=validateRuntimeCertificateEndpoint(struct{}{},"tailnet");err==nil||!strings.Contains(err.Error(),"staged runtime resource adapter"){t.Fatal("missing endpoint lifecycle hidden",err)}
 failure:=errors.New("endpoint still owns unjoined worker")
 if _,err:=validateRuntimeCertificateEndpoint(certificateEndpointFixture{err:failure},"tailnet");!errors.Is(err,failure){t.Fatal("endpoint lifecycle failure replaced",err)}
 if _,err:=validateRuntimeCertificateEndpoint(certificateEndpointFixture{},"tailnet");err==nil{t.Fatal("zero endpoint resource identity admitted")}
 expected:=adapter.RuntimeResourceID{Incarnation:"tailscale-certificate-fixture",Sequence:1}
 if actual,err:=validateRuntimeCertificateEndpoint(certificateEndpointFixture{id:expected},"tailnet");err!=nil||actual!=expected{t.Fatal("exact endpoint identity lost",actual,err)}
}
func tailscaleCertificateOwner(t *testing.T,sequence uint64,deps []adapter.RuntimeResourceLease,closeFn func()error)*runtimegraph.ResourceOwner{
 t.Helper();owner,err:=runtimegraph.NewResourceOwner(context.Background(),adapter.RuntimeResourceID{Incarnation:"tailscale-certificate-fixture",Sequence:sequence},deps,closeFn);if err!=nil{t.Fatal(err)};return owner
}
func tailscaleCertificateWait(t *testing.T,owner *runtimegraph.ResourceOwner){t.Helper();ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel();if err:=owner.WaitClosed(ctx);err!=nil{t.Fatal(err)}}
func TestTailscaleCertificateCallbackCannotFallBackToUncapturedEndpoint(t *testing.T){
 endpoint:=tailscaleCertificateOwner(t,2,nil,nil)
 fence:=outbound.NewRuntimeIOFence(nil)
 owner:=tailscaleCertificateOwner(t,3,nil,fence.RuntimeCloseAndWait)
 provider:=&CertificateProvider{runtime:&runtimeCertificateProvider{source:owner,endpointID:endpoint.ID(),fence:fence,active:true}}
 if _,err:=provider.GetCertificateWithContext(context.Background(),&tls.ClientHelloInfo{});err==nil||err.Error()=="no SNI ServerName"{t.Fatal("callback reached endpoint-dependent body without captured edge",err)}
 ids:=provider.RuntimeDependencies();ids[0]=adapter.RuntimeResourceID{}
 if provider.RuntimeDependencies()[0]!=endpoint.ID(){t.Fatal("mutable endpoint dependency slice escaped")}
 owner.Seal();endpoint.Seal();tailscaleCertificateWait(t,owner);tailscaleCertificateWait(t,endpoint)
}
func TestTailscaleCertificateCallbackRetainsExactOldEndpoint(t *testing.T){
 endpoint:=tailscaleCertificateOwner(t,4,nil,nil)
 dependency,err:=endpoint.Acquire();if err!=nil{t.Fatal(err)}
 fence:=outbound.NewRuntimeIOFence(nil)
 owner:=tailscaleCertificateOwner(t,5,[]adapter.RuntimeResourceLease{dependency},fence.RuntimeCloseAndWait);dependency.Release()
 request,err:=owner.Acquire();if err!=nil{t.Fatal(err)}
 provider:=&CertificateProvider{runtime:&runtimeCertificateProvider{source:owner,endpointID:endpoint.ID(),fence:fence,active:true}}
 owner.Seal();endpoint.Seal()
 _,err=provider.GetCertificateWithContext(adapter.ContextWithRuntimeResourceLease(context.Background(),request),&tls.ClientHelloInfo{})
 if err==nil||err.Error()!="no SNI ServerName"{t.Fatal("exact old endpoint continuation rejected before body",err)}
 request.Release();tailscaleCertificateWait(t,owner);tailscaleCertificateWait(t,endpoint)
 if _,err:=provider.GetCertificateWithContext(context.Background(),&tls.ClientHelloInfo{});err==nil||err.Error()=="no SNI ServerName"{t.Fatal("retired provider reopened root admission",err)}
}
