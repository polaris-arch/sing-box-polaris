package v2raygrpc

import (
 "context"
 "net"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/transport/runtimeingress"
 "google.golang.org/grpc/credentials"
)

// AuthInfo is the gRPC-supported per-physical-connection handoff. It carries
// exactly that carrier's borrowed lineage, with the underlying TLS info intact.
type runtimeServerAuth struct{credentials.AuthInfo;context context.Context}
func(a *runtimeServerAuth)AuthType()string{if a.AuthInfo==nil{return "runtime-ingress"};return a.AuthInfo.AuthType()}
type runtimeServerCredentials struct{inner credentials.TransportCredentials}
func(c *runtimeServerCredentials)ServerHandshake(raw net.Conn)(net.Conn,credentials.AuthInfo,error){
 lineage:=runtimeingress.Context(context.Background(),raw)
 if _,ok:=adapter.RuntimeLeaseFromContext(lineage);!ok{return nil,nil,net.ErrClosed}
 owned,leave,err:=runtimeingress.Acquire(lineage,true);if err!=nil{return nil,nil,err};defer leave()
 _=owned // the invocation pin protects an optional TLS handshake below.
 conn:=raw;var info credentials.AuthInfo
 if c.inner!=nil{conn,info,err=c.inner.ServerHandshake(raw);if err!=nil{return nil,nil,err}}
 return conn,&runtimeServerAuth{AuthInfo:info,context:lineage},nil
}
func(c *runtimeServerCredentials)ClientHandshake(context.Context,string,net.Conn)(net.Conn,credentials.AuthInfo,error){return nil,nil,net.ErrClosed}
func(c *runtimeServerCredentials)Info()credentials.ProtocolInfo{if c.inner!=nil{return c.inner.Info()};return credentials.ProtocolInfo{SecurityProtocol:"insecure"}}
func(c *runtimeServerCredentials)Clone()credentials.TransportCredentials{var inner credentials.TransportCredentials;if c.inner!=nil{inner=c.inner.Clone()};return &runtimeServerCredentials{inner:inner}}
func(c *runtimeServerCredentials)OverrideServerName(name string)error{if c.inner!=nil{return c.inner.OverrideServerName(name)};return nil}

func(a *runtimeServerAuth)GetCommonAuthInfo()credentials.CommonAuthInfo{
 if info,ok:=a.AuthInfo.(interface{GetCommonAuthInfo()credentials.CommonAuthInfo});ok{return info.GetCommonAuthInfo()}
 return credentials.CommonAuthInfo{SecurityLevel:credentials.NoSecurity}
}
