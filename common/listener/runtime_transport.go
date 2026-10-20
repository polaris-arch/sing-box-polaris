package listener

import (
 "errors"

 "github.com/sagernet/sing-box/adapter"
)

// BindRuntimeStreamHandler installs a private transport acceptor before socket
// staging. It cannot replace a handler after worker publication.
func(l *Listener)BindRuntimeStreamHandler(handler adapter.ConnectionHandler)error{
 if l.runtime==nil||handler==nil{return errors.New("missing staged listener or transport handler")}
 l.runtime.mu.Lock();defer l.runtime.mu.Unlock()
 if l.runtime.phase!="inert"{return ErrRuntimeTransition}
 l.connHandler=handler
 return nil
}

// DeclareRuntimePacketTransport records a concrete constructor's staged packet
// capability. Validate may run before its private endpoint is prepared; Prepare
// still requires the real handler and never treats this declaration as binding.
func(l *Listener)DeclareRuntimePacketTransport()error{
 if l.runtime==nil{return ErrRuntimeRawTransport}
 l.runtime.mu.Lock();defer l.runtime.mu.Unlock()
 if l.runtime.phase!="inert"{return ErrRuntimeTransition}
 l.runtime.packetTransportDeclared=true
 return nil
}
