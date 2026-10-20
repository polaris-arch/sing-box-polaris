//go:build with_quic

package quic

import (
 "context"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "sync"
 "time"

 "github.com/sagernet/quic-go"
 "github.com/sagernet/quic-go/congestion"
 "github.com/sagernet/quic-go/http3"
 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/outbound"
 "github.com/sagernet/sing-box/common/listener"
 "github.com/sagernet/sing-box/common/tls"
 "github.com/sagernet/sing-box/option"
 "github.com/sagernet/sing-box/protocol/naive"
 "github.com/sagernet/sing-box/transport/runtimeingress"
 qtls "github.com/sagernet/sing-quic"
 congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
 congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
 "github.com/sagernet/sing/common"
 "github.com/sagernet/sing/common/logger"
 "github.com/sagernet/sing/common/ntp"
)

func init(){naive.PrepareRuntimeHTTP3ListenerFunc=prepareRuntimeHTTP3}

type runtimeHTTP3Server struct{
 endpoint *runtimeingress.QUICEndpoint
 server *http3.Server
 callbacks *outbound.RuntimeIOFence
 done chan struct{}
 ready chan struct{}
 readyOnce sync.Once
 err error
 failureMu sync.Mutex
 failure error
}
func prepareRuntimeHTTP3(ctx context.Context,_ logger.Logger,ingress *listener.Listener,handler http.Handler,config tls.ServerConfig,options option.NaiveInboundOptions)(io.Closer,error){
 if err:=tls.ValidateRuntimeServer(config);err!=nil{return nil,err}
 if err:=qtls.ConfigureHTTP3(config);err!=nil{return nil,err}
 if !common.Contains(config.NextProtos(),http3.NextProtoH3){config.SetNextProtos(append(append([]string{},config.NextProtos()...),http3.NextProtoH3))}
 // The constructor installed a clock-provider fence in ctx. No current graph
 // or global clock service is reacquired from this native congestion callback.
 clock:=ntp.TimeFuncFromContext(ctx);if clock==nil{clock=time.Now}
 var congestionControl func(*quic.Conn)congestion.CongestionControl
 switch options.QUICCongestionControl{
 case "","bbr":congestionControl=func(c *quic.Conn)congestion.CongestionControl{return congestion_meta2.NewBbrSenderWithProfile(c.InitialPacketSize(),congestion_meta2.ProfileStandard)}
 case "cubic","reno":
  reno:=options.QUICCongestionControl=="reno"
  congestionControl=func(c *quic.Conn)congestion.CongestionControl{return congestion_meta1.NewCubicSender(congestion_meta1.DefaultClock{TimeFunc:clock},c.InitialPacketSize(),reno)}
 default:return nil,errors.New("unknown Naive QUIC congestion control")
 }
 endpoint,err:=runtimeingress.ListenQUIC(ctx,ingress,config,newQUICConfig(),true)
 if err!=nil{return nil,err}
 s:=&runtimeHTTP3Server{endpoint:endpoint,done:make(chan struct{}),ready:make(chan struct{})}
 s.callbacks=outbound.NewRuntimeIOFence(func()error{
  // Both concrete native readers are interrupted before waiting for Serve.
  endpointErr:=endpoint.Close()
  serverErr:=s.server.Close()
  <-s.done
  err:=errors.Join(endpointErr,serverErr)
  if s.err!=nil&&!errors.Is(s.err,http.ErrServerClosed)&&!errors.Is(s.err,net.ErrClosed){err=errors.Join(err,s.err)}
  if err!=nil{return fmt.Errorf("Naive HTTP3 cleanup incomplete: %v",err)}
  return nil
 })
 s.server=&http3.Server{Handler:handler,ConnContext:func(request context.Context,connection *quic.Conn)(result context.Context){
  result=request
  leave,err:=s.callbacks.Acquire()
  if err!=nil{_ = connection.CloseWithError(0,"");return request}
  defer leave()
  _,release,err:=runtimeingress.Acquire(connection.Context(),true)
  if err!=nil{_ = connection.CloseWithError(0,"");return request}
  returned:=false
  defer func(){
   value:=recover()
   if value!=nil||!returned{
    s.record(fmt.Errorf("HTTP3 connection callback did not complete (panic=%v)",value))
    _ = connection.CloseWithError(0,"")
    // Preserve the unknown callback operation, but join its actual return.
    return
   }
   release()
  }()
  connection.SetCongestionControl(congestionControl(connection))
  result=adapter.ContextWithRuntimeOwnership(request,connection.Context())
  returned=true
  return result
 }}
 go func(){
  returned:=false
  defer close(s.done)
  defer func(){if value:=recover();value!=nil||!returned{s.err=fmt.Errorf("Naive HTTP3 Serve did not complete (panic=%v)",value)}}()
  s.err=s.server.ServeListener(runtimeHTTP3Listener{server:s})
  returned=true
 }()
 if err:=adapter.DeferConstructionCleanup(ctx,s.Close);err!=nil{return nil,errors.Join(err,s.Close())}
 select{
 case <-s.ready:
  select{case <-s.done:return nil,errors.Join(errors.New("HTTP3 Serve stopped at private readiness"),s.Close());default:}
  if err:=adapter.ConstructionScopeErr(ctx);err!=nil{return nil,errors.Join(err,s.Close())}
  return s,nil
 case <-s.done:err=s.err;if err==nil{err=errors.New("HTTP3 Serve exited before private readiness")}
 case <-ctx.Done():err=ctx.Err()
 }
 return nil,errors.Join(err,s.Close())
}
func(s *runtimeHTTP3Server)Accept(ctx context.Context)(*quic.Conn,error){s.readyOnce.Do(func(){close(s.ready)});return s.endpoint.Accept(ctx)}
func(s *runtimeHTTP3Server)Addr()net.Addr{return s.endpoint.Addr()}
// ServeListener closes its supplied listener while unwinding. Its listener view
// must close only the endpoint, never wait on that same Serve goroutine.
type runtimeHTTP3Listener struct{server *runtimeHTTP3Server}
func(l runtimeHTTP3Listener)Accept(ctx context.Context)(*quic.Conn,error){return l.server.Accept(ctx)}
func(l runtimeHTTP3Listener)Addr()net.Addr{return l.server.Addr()}
func(l runtimeHTTP3Listener)Close()error{return l.server.endpoint.Close()}
func(s *runtimeHTTP3Server)record(err error){
 s.failureMu.Lock();s.failure=errors.Join(s.failure,fmt.Errorf("HTTP3 lifetime incomplete: %v",err));s.failureMu.Unlock()
 _=s.callbacks.Close()
}
func(s *runtimeHTTP3Server)Close()error{
 err:=s.callbacks.RuntimeCloseAndWait()
 s.failureMu.Lock();defer s.failureMu.Unlock()
 return errors.Join(err,s.failure)
}
func(s *runtimeHTTP3Server)RuntimeCloseAndWait()error{return s.Close()}
