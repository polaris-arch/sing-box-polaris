package hysteria2

import (
 "context"
 "errors"
 "net"
 "sync"
 "sync/atomic"
)

// clientRuntime owns every ordinary client worker, including discarded offers
// and connection generations replaced by network or idle closure. It is not a
// graph lease: the embedding adapter owns its immutable dependency closure.
type clientRuntime struct {
 mu sync.Mutex
 closed atomic.Bool
 workers sync.WaitGroup
 connections map[*clientQUICConnection]struct{}
 cancel context.CancelFunc
 closeOnce sync.Once
 closeErr error
}
func(c *Client)initRuntime(){
 ctx:=c.ctx;if ctx==nil{ctx=context.Background()}
 c.ctx,c.runtime.cancel=context.WithCancel(ctx)
 c.runtime.connections=make(map[*clientQUICConnection]struct{})
}
func(r *clientRuntime)run(task func())bool{
 r.mu.Lock()
 if r.closed.Load(){r.mu.Unlock();return false}
 r.workers.Add(1)
 r.mu.Unlock()
 go func(){defer r.workers.Done();task()}()
 return true
}
func(r *clientRuntime)register(conn *clientQUICConnection){
 r.mu.Lock();conn.runtimeOwner=r;r.connections[conn]=struct{}{};closed:=r.closed.Load();r.mu.Unlock()
 if closed{conn.closeWithError(net.ErrClosed)}
}
func(c *Client)runConnectionTask(conn *clientQUICConnection, task func())bool{
 if c.runtime.run(task){return true}
 conn.closeWithError(net.ErrClosed)
 return false
}
// RuntimeCloseAndWait is terminal. CloseWithError remains a reusable network
// reset and must never be substituted for this terminal worker join.
func(c *Client)RuntimeCloseAndWait()error{
 c.runtime.closeOnce.Do(func(){
  c.runtime.mu.Lock();c.runtime.closed.Store(true)
  connections:=make([]*clientQUICConnection,0,len(c.runtime.connections))
  for conn:=range c.runtime.connections{connections=append(connections,conn)}
  c.runtime.mu.Unlock()
  c.runtime.cancel()
  if c.realmOptions!=nil{c.runtime.mu.Lock();c.runtime.closeErr=errors.Join(c.runtime.closeErr,errors.New("optional Realm registration/punch/port-mapper worker completion is outside ordinary client runtime contract"));c.runtime.mu.Unlock()}
  _=c.CloseWithError(net.ErrClosed)
  for _,conn:=range connections{conn.closeWithError(net.ErrClosed)}
  c.runtime.workers.Wait()
  // Late offers registered their transport before leaving the counted worker.
  c.runtime.mu.Lock();connections=connections[:0]
  for conn:=range c.runtime.connections{connections=append(connections,conn)}
  c.runtime.mu.Unlock()
  for _,conn:=range connections{conn.closeTransport()}
 })
 c.runtime.mu.Lock();defer c.runtime.mu.Unlock();return c.runtime.closeErr
}

// Closing a replaced session also cancels an in-flight port hop, without
// canceling the reusable client or any newer physical session.
type clientCancelableConn struct{net.Conn;cancel context.CancelFunc}
func(c *clientCancelableConn)Close()error{c.cancel();return c.Conn.Close()}
func(c *clientCancelableConn)Upstream()any{return c.Conn}

func(c *clientCancelableConn)IOActivityFuncs()(func(int),func(int)){
 if accounting,ok:=c.Conn.(interface{IOActivityFuncs()(func(int),func(int))});ok{return accounting.IOActivityFuncs()}
 return nil,nil
}

func(r *clientRuntime)retire(conn *clientQUICConnection,err error){
 r.mu.Lock();defer r.mu.Unlock()
 delete(r.connections,conn)
 r.closeErr=errors.Join(r.closeErr,err)
}
