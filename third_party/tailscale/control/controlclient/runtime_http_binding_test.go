package controlclient

import (
 "context"
 "io"
 "net/http"
 "strings"
 "testing"
)

type runtimeBindingRoundTrip func(*http.Request)(*http.Response,error)
func(f runtimeBindingRoundTrip)RoundTrip(r *http.Request)(*http.Response,error){return f(r)}
type runtimeBindingBody struct{io.Reader;close func()}
func(b *runtimeBindingBody)Close()error{b.close();return nil}

func TestRuntimeHTTPBindingCoversRedirectAndFinalBody(t *testing.T){
 acquisitions,releases,requests,bodies:=0,0,0,0
 client:=&http.Client{Transport:runtimeBindingRoundTrip(func(request *http.Request)(*http.Response,error){
  requests++
  if releases!=0{t.Fatal("operation binding released before final redirect/body")}
  response:=&http.Response{StatusCode:200,Header:make(http.Header),Body:&runtimeBindingBody{Reader:strings.NewReader("{}"),close:func(){bodies++}},Request:request}
  if requests==1{response.StatusCode=302;response.Header.Set("Location","/final")}
  return response,nil
 })}
 direct:=&Direct{serverURL:"https://control.invalid",acquireHTTPClient:func(context.Context)(*http.Client,func(),error){acquisitions++;return client,func(){
  if bodies!=2{t.Errorf("release preceded original response close: %d",bodies)}
  releases++
 },nil}}
 if _,err:=direct.loadServerPubKeysBound(context.Background());err!=nil{t.Fatal(err)}
 if acquisitions!=1||releases!=1||requests!=2{t.Fatalf("unexpected lifecycle %d/%d/%d",acquisitions,releases,requests)}
}
