//go:build !js && !ts_omit_acme

package tsnet

import (
 "context"
 "io"
 "net/http"
 "testing"
 "time"

 "github.com/sagernet/tailscale/client/local"
 "github.com/sagernet/tailscale/client/tailscale/apitype"
)

type runtimeCertificateTestKey struct{}
func TestRuntimeCertificateContextAndOriginalPairConversion(t *testing.T){
 const key="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
 const cert="-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"
 marker:=new(int)
 transport:=&runtimeCertificateTransport{handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Context().Value(runtimeCertificateTestKey{})!=marker{t.Error("operation context was lost")}
  if r.Host!=apitype.LocalAPIHost||r.Method!="GET"||r.URL.Path!="/localapi/v0/cert/node.example"||r.URL.Query().Get("min_validity")!="1h0m0s"{t.Errorf("changed original request: %v",r)}
  _,_=io.WriteString(w,key+cert)
 })}
 client:=&local.Client{Transport:transport}
 gotCert,gotKey,err:=client.CertPairWithValidity(context.WithValue(context.Background(),runtimeCertificateTestKey{},marker),"node.example",time.Hour)
 if err!=nil||string(gotCert)!=cert||string(gotKey)!=key{t.Fatalf("original conversion changed: cert=%q key=%q err=%v",gotCert,gotKey,err)}
}
func TestRuntimeCertificateOriginalRateLimitConversion(t *testing.T){
 client:=&local.Client{Transport:&runtimeCertificateTransport{handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("Retry-After","23");http.Error(w,"limited",http.StatusTooManyRequests)})}}
 _,_,err:=client.CertPairWithValidity(context.Background(),"node.example",0)
 delay,ok:=local.RateLimitRetryAfter(err)
 if !ok||delay!=23*time.Second{t.Fatalf("original rate limit semantics changed: %v, %v",delay,err)}
}
func TestRuntimeCertificateCloseJoinsOriginalHandler(t *testing.T){
 entered,release,returned:=make(chan struct{}),make(chan struct{}),make(chan struct{})
 transport:=&runtimeCertificateTransport{handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  defer close(returned)
  w.WriteHeader(http.StatusOK);close(entered)
  <-r.Context().Done();<-release
 })}
 req,_:=http.NewRequest("GET","http://"+apitype.LocalAPIHost+"/localapi/v0/cert/node.example",nil)
 response,err:=transport.RoundTrip(req);if err!=nil{t.Fatal(err)};<-entered
 closed:=make(chan struct{});go func(){_ = response.Body.Close();close(closed)}()
 // The handler is blocked on release even after cancellation. Completion must
 // remain blocked until that exact original invocation returns.
 select{case <-closed:t.Fatal("body close fabricated handler completion");default:}
 close(release);<-closed
 select{case <-returned:default:t.Fatal("body close preceded original handler return")}
}
func TestRuntimeCertificateCancellationBeforeHeadersJoins(t *testing.T){
 entered,release,returned:=make(chan struct{}),make(chan struct{}),make(chan struct{})
 transport:=&runtimeCertificateTransport{handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){defer close(returned);close(entered);<-r.Context().Done();<-release})}
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 req,_:=http.NewRequestWithContext(ctx,"GET","http://"+apitype.LocalAPIHost+"/localapi/v0/cert/node.example",nil)
 finished:=make(chan struct{});go func(){response,err:=transport.RoundTrip(req);if response!=nil{_ = response.Body.Close()};if err==nil{t.Error("missing cancellation error")};close(finished)}()
 <-entered;cancel()
 select{case <-finished:t.Fatal("canceled request fabricated handler return");default:}
 close(release);<-finished;<-returned
}
func TestRuntimeCertificateRejectsOtherDecodedActions(t *testing.T){
 transport:=&runtimeCertificateTransport{handler:http.HandlerFunc(func(http.ResponseWriter,*http.Request){t.Error("noncertificate action reached handler")})}
 for _,path:=range []string{"/localapi/v0/status","/localapi/v0/%73tatus","/localapi/v0/cert%2f..%2f..%2fstatus"}{
  req,_:=http.NewRequest("POST","http://"+apitype.LocalAPIHost+path,nil)
  if _,err:=transport.RoundTrip(req);err==nil{t.Fatal("non-GET action admitted")}
 }
 req,_:=http.NewRequest("GET","http://"+apitype.LocalAPIHost+"/localapi/v0/%73tatus",nil)
 if _,err:=transport.RoundTrip(req);err==nil{t.Fatal("decoded noncertificate action admitted")}
}
