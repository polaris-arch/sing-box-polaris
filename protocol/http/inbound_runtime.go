package http

import (
 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/inbound"
 "github.com/sagernet/sing-box/common/listener"
 "github.com/sagernet/sing-box/common/tls"
)

var _ inbound.RuntimePreparedInbound = (*Inbound)(nil)
func(h *Inbound)RuntimeValidate()error{
 if err:=h.listener.ValidateRuntime();err!=nil{return err}
 return tls.ValidateRuntimeServer(h.tlsConfig)
}
func(h *Inbound)RuntimeListeners()[]*listener.Listener{return []*listener.Listener{h.listener}}
func(h *Inbound)PrepareRuntime(stage adapter.StartStage,_ *adapter.Scope)error{
 if err:=h.RuntimeValidate();err!=nil{return err}
 if stage==adapter.StartStateStart{
  if h.tlsConfig!=nil{if err:=h.tlsConfig.Start();err!=nil{return err}}
  if h.http3{return h.startHTTP3(nil)}
 }
 return nil
}
