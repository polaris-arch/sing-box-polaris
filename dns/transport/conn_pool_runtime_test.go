package transport

import (
 "context"
 "errors"
 "sync"
 "testing"
 "time"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/internal/runtimegraph"
)

func TestSharedPoolCanceledWaiterRetainsCreationAndLateClose(t *testing.T){
 watchdog,stop:=context.WithTimeout(context.Background(),5*time.Second);defer stop()
 owner,err:=runtimegraph.NewResourceOwner(context.Background(),adapter.RuntimeResourceID{Incarnation:"shared-pool",Sequence:1},nil,func()error{return nil})
 if err!=nil{t.Fatal(err)}
 parent,err:=owner.Acquire();if err!=nil{t.Fatal(err)};defer parent.Release()
 ctx,cancel:=context.WithCancel(adapter.ContextWithRuntimeResourceLease(watchdog,parent));defer cancel()
 entered,releaseDial,closeEntered,releaseClose:=make(chan struct{}),make(chan struct{}),make(chan struct{}),make(chan struct{})
 var dialOnce,closeOnce sync.Once
 unblockDial:=func(){dialOnce.Do(func(){close(releaseDial)})};defer unblockDial()
 unblockClose:=func(){closeOnce.Do(func(){close(releaseClose)})};defer unblockClose()
 pool:=NewConnPool(ConnPoolOptions[int]{Mode:ConnPoolSingle,IsAlive:func(int)bool{return true},Close:func(int,error){close(closeEntered);<-releaseClose}})
 returned:=make(chan error,1)
 go func(){_,_,_,err:=pool.AcquireShared(ctx,func(owned context.Context)(int,error){
  if _,ok:=adapter.RuntimeResourceLeaseFromContext(owned,owner.ID());!ok{panic("lost creation continuation")}
  close(entered);<-releaseDial;return 1,nil
 });returned<-err}()
 select{case <-entered:case <-watchdog.Done():t.Fatal(watchdog.Err())}
 cancel()
 select{case err:=<-returned:if !errors.Is(err,context.Canceled){t.Fatal(err)};case <-watchdog.Done():t.Fatal(watchdog.Err())}
 parent.Release();owner.Seal()
 select{case <-owner.Closed():t.Fatal("canceled waiter freed live creation");default:}
 unblockDial()
 select{case <-closeEntered:case <-watchdog.Done():t.Fatal(watchdog.Err())}
 select{case <-owner.Closed():t.Fatal("late physical close freed before completion");default:}
 unblockClose()
 if err:=owner.WaitClosed(watchdog);err!=nil{t.Fatal(err)}
 if err:=pool.Close();err!=nil{t.Fatal(err)}
}
