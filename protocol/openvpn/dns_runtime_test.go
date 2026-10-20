package openvpn

import (
 "context"
 "errors"
 "net/netip"
 "testing"
 "time"

 "github.com/sagernet/sing-box/dns/transport/lifecycle"
 "github.com/sagernet/sing-box/log"
)
func fixtureEndpointDNS()*DNSTransport{
 ctx,cancel:=context.WithCancel(context.Background());producer,stop:=context.WithCancel(ctx)
 return &DNSTransport{ctx:ctx,operationCtx:ctx,operationCancel:cancel,producerCtx:producer,producerCancel:stop,logger:log.NewNOPFactory().Logger()}
}
func TestEndpointDNSCloseWaitsForCallback(t *testing.T){
 dns:=fixtureEndpointDNS();release,ok:=dns.work.Reserve();if !ok{t.Fatal("reserve")}
 done:=make(chan struct{});go func(){defer close(done);_ = dns.close()}()
 <-dns.operationCtx.Done();select{case <-done:t.Fatal("close skipped callback");default:}
 release();select{case <-done:case <-time.After(5*time.Second):t.Fatal("callback not joined")}
}
func TestEndpointDNSRetirementFailureRemainsSticky(t *testing.T){
 dns:=fixtureEndpointDNS();scope,err:=dns.scopes.New(dns.operationCtx,dns.logger);if err!=nil{t.Fatal(err)}
 scope.Add(func()error{return errors.New("socket close failed")});dns.scopes.Retire(scope)
 first:=dns.close();if first==nil||dns.close()!=first{t.Fatal("cohort failure forgotten")}
}
func TestEndpointDNSMetadataIsDetached(t *testing.T){
 dns:=fixtureEndpointDNS();defer dns.close();original:=netip.MustParseAddr("192.0.2.1");dns.serverAddresses=[]netip.Addr{original};dns.searchDomains=[]string{"example."}
 addresses:=dns.ServerAddresses();domains:=dns.SearchDomains();addresses[0]=netip.Addr{};domains[0]="changed."
 if dns.serverAddresses[0]!=original||dns.searchDomains[0]!="example."{t.Fatal("metadata escaped mutable owner")}
}
func TestEndpointDNSProducerCancellationLinksExactOwner(t *testing.T){
 dns:=fixtureEndpointDNS();defer dns.close();ctx,cancel:=context.WithCancel(context.Background())
 dns.producerCtx,dns.endpointUnlink=lifecycle.LinkCancellation(dns.producerCtx,ctx)
 cancel();select{case <-dns.producerCtx.Done():case <-time.After(5*time.Second):t.Fatal("retiring endpoint failed to interrupt configuration producer")}
}
