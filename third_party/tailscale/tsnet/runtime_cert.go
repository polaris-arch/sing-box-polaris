// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

package tsnet

import (
 "context"
 "errors"
 "fmt"
 "io"
 "net/http"
 "strings"
 "sync"
 "time"

 "github.com/sagernet/tailscale/client/local"
 "github.com/sagernet/tailscale/client/tailscale/apitype"
)

// RuntimeCertificatePair preserves the original certificate LocalAPI handler
// and client status/Retry-After/PEM conversion while carrying the caller's exact
// operation context into the in-process handler. The caller owns that context
// until this method returns, including every original handler invocation.
// Other LocalAPI operations cannot use this certificate-only transport.
func(s *Server)RuntimeCertificatePair(ctx context.Context,domain string,minValidity time.Duration)([]byte,[]byte,error){
 if err:=s.Start();err!=nil{return nil,nil,err}
 if s.localAPIServer==nil||s.localAPIServer.Handler==nil{return nil,nil,errors.New("Tailscale certificate LocalAPI handler unavailable")}
 client:=&local.Client{Transport:&runtimeCertificateTransport{handler:s.localAPIServer.Handler}}
 return client.CertPairWithValidity(ctx,domain,minValidity)
}

type runtimeCertificateTransport struct{handler http.Handler}

func(t *runtimeCertificateTransport)RoundTrip(request *http.Request)(*http.Response,error){
 // URL.Path is already decoded by net/url. The original handler dispatches
 // this exact path without path cleaning; a cert prefix cannot reach another
 // LocalAPI action even if a caller supplies a slash in the domain.
 if request==nil||request.URL==nil||request.Method!=http.MethodGet||request.URL.Scheme!="http"||request.URL.Host!=apitype.LocalAPIHost||request.Host!=apitype.LocalAPIHost||request.URL.User!=nil||!strings.HasPrefix(request.URL.Path,"/localapi/v0/cert/"){
  return nil,errors.New("invalid certificate-only LocalAPI request")
 }
 if t.handler==nil{return nil,errors.New("missing certificate LocalAPI handler")}
 ctx,cancel:=context.WithCancel(request.Context())
 reader,writer:=io.Pipe()
 done:=make(chan struct{})
 headers:=make(chan *http.Response,1)
 body:=&runtimeCertificateBody{reader:reader,cancel:cancel,done:done,cancelDone:make(chan struct{})}
 body.stopCancel=context.AfterFunc(ctx,func(){_ = reader.CloseWithError(ctx.Err());close(body.cancelDone)})
 outgoing:=request.Clone(ctx)
 outgoing.RequestURI=outgoing.URL.RequestURI()
 response:=&runtimeCertificateWriter{header:make(http.Header),writer:writer,headers:headers,request:request,body:body}
 // done is reserved before launch and closes only after the original handler
 // actually returns or unwinds. Closing the body cannot manufacture its return.
 go func(){
  defer close(done)
  defer func(){
   if recover()!=nil{_ = writer.CloseWithError(io.ErrUnexpectedEOF);return}
   response.WriteHeader(http.StatusOK)
   _ = writer.Close()
  }()
  t.handler.ServeHTTP(response,outgoing)
 }()
 select{
 case result:=<-headers:
  if err:=ctx.Err();err!=nil{_ = body.Close();return nil,err}
  return result,nil
 case <-ctx.Done():
  _ = body.Close();return nil,ctx.Err()
 case <-done:
  select{case result:=<-headers:if err:=ctx.Err();err!=nil{_ = body.Close();return nil,err};return result,nil;default:_ = body.Close();return nil,io.ErrUnexpectedEOF}
 }
}

// The pipe adds no response buffering. The unchanged local.Client applies its
// original response parsing and buffering policy. Close wakes blocked writes,
// cancels the exact handler context and joins its original invocation.
type runtimeCertificateBody struct{
 reader *io.PipeReader
 cancel context.CancelFunc
 done chan struct{}
 cancelDone chan struct{}
 stopCancel func()bool
 once sync.Once
 err error
}
func(b *runtimeCertificateBody)Read(p []byte)(int,error){return b.reader.Read(p)}
func(b *runtimeCertificateBody)Close()error{
 b.once.Do(func(){b.cancel();b.err=b.reader.Close();if !b.stopCancel(){<-b.cancelDone};<-b.done})
 return b.err
}

type runtimeCertificateWriter struct{
 header http.Header
 writer *io.PipeWriter
 headers chan *http.Response
 request *http.Request
 body *runtimeCertificateBody
 wroteHeader bool
}
func(w *runtimeCertificateWriter)Header()http.Header{return w.header}
func(w *runtimeCertificateWriter)WriteHeader(status int){
 if w.wroteHeader{return}
 // The original cert handler emits only final responses. Honor net/http's
 // informational behavior without treating a 1xx header as the final body.
 if status>=100&&status<200{return}
 w.wroteHeader=true
 w.headers<-&http.Response{StatusCode:status,Status:fmt.Sprintf("%d %s",status,http.StatusText(status)),Header:w.header.Clone(),Body:w.body,ContentLength:-1,Proto:"HTTP/1.1",ProtoMajor:1,ProtoMinor:1,Request:w.request}
}
func(w *runtimeCertificateWriter)Write(p []byte)(int,error){w.WriteHeader(http.StatusOK);return w.writer.Write(p)}
