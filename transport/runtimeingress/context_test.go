package runtimeingress

import (
 "context"
 "net"
 "sync/atomic"
 "testing"

 "github.com/sagernet/sing-box/adapter"
)

type fixtureLease struct{released atomic.Bool;forks *atomic.Int32}
func(l *fixtureLease)View()adapter.RuntimeView{return nil}
func(l *fixtureLease)Fork()(adapter.RuntimeLease,error){if l.released.Load(){return nil,net.ErrClosed};l.forks.Add(1);return &fixtureLease{forks:l.forks},nil}
func(l *fixtureLease)RetainResource(adapter.RuntimeResourceID)(adapter.RuntimeResourceLease,error){return nil,net.ErrClosed}
func(l *fixtureLease)Release(){l.released.Store(true)}
type tlsFixtureConn struct{net.Conn;inner net.Conn}
func(c *tlsFixtureConn)NetConn()net.Conn{return c.inner}

func TestRuntimeIngressUsesPhysicalLineageThroughTLS(t *testing.T){
 var forks atomic.Int32
 lease:=&fixtureLease{forks:&forks}
 physical:=adapter.ContextWithRuntimeLease(context.Background(),lease)
 conn:=&tlsFixtureConn{inner:&Conn{Context:physical}}
 borrowed:=Context(context.Background(),conn)
 got,ok:=adapter.RuntimeLeaseFromContext(borrowed);if !ok||got!=lease{t.Fatal("physical lineage was lost")}
 _,leave,err:=Acquire(borrowed,true);if err!=nil{t.Fatal(err)};leave()
 if forks.Load()!=1{t.Fatal("request did not fork exact physical lineage")}
 lease.Release()
 if _,_,err=Acquire(borrowed,true);err==nil{t.Fatal("released physical lineage was reacquired")}
}
func TestRuntimeIngressRejectsUnmarkedStagedRequests(t *testing.T){
 if _,_,err:=Acquire(context.Background(),true);err==nil{t.Fatal("staged request borrowed current graph")}
 _,leave,err:=Acquire(context.Background(),false);if err!=nil{t.Fatal(err)};leave()
}

func TestRuntimeSessionOwnershipEndsAtConcreteContext(t *testing.T){
 connection,cancel:=context.WithCancel(context.Background())
 released:=make(chan struct{})
 var calls atomic.Int32
 own,err:=BindSession(connection,func(ctx context.Context)(context.Context,func(),error){return ctx,func(){calls.Add(1);close(released)},nil})
 if err!=nil||own!=connection{t.Fatal("session admission changed context")}
 select{case <-released:t.Fatal("session released before terminal cancellation");default:}
 cancel();<-released;cancel()
 if calls.Load()!=1{t.Fatal("terminal release repeated")}
}
func TestRuntimeSessionAdmissionFailureCreatesNoLease(t *testing.T){
 if _,err:=BindSession(context.Background(),func(context.Context)(context.Context,func(),error){return nil,nil,net.ErrClosed});err==nil{t.Fatal("failed session was accepted")}
}
