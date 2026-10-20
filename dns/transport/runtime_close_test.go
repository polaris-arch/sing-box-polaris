package transport

import (
 "context"
 "errors"
 "net"
 "sync/atomic"
 "testing"
)

type runtimeDNSFailClose struct{net.Conn;calls atomic.Int32;panicClose bool}
func(c *runtimeDNSFailClose)Close()error{c.calls.Add(1);if c.panicClose{panic("close failed")};return net.ErrClosed}
func TestDNSCarrierCleanupUncertaintyReachesTerminalOwner(t *testing.T){
 for _,panicClose:=range []bool{false,true}{
  raw:=&runtimeDNSFailClose{panicClose:panicClose}
  m:=newQueryMultiplexer(queryMultiplexerOptions{context:context.Background(),dial:func(context.Context)(net.Conn,error){return raw,nil}})
  conn,err:=m.options.dial(context.Background());if err!=nil{t.Fatal(err)}
  _=conn.Close() // Includes generic pool's void close callback behavior.
  _=conn.Close()
  err=m.Close()
  if err==nil||!runtimeDNSCleanupIncomplete(err){t.Fatal("carrier failure was discarded",err)}
  if errors.Is(err,net.ErrClosed){t.Fatal("Scope could filter uncertainty as ordinary closed")}
  if raw.calls.Load()!=1{t.Fatal("cleanup was not one-shot")}
 }
}
