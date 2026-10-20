package box

import (
 "context"
 "testing"
 "time"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/internal/runtimegraph"
)

func TestRuntimeClockWriterRequiresExactActiveResource(t *testing.T){
 id:=adapter.RuntimeResourceID{Incarnation:"clock",Sequence:7}
 owner,err:=runtimegraph.NewResourceOwner(context.Background(),id,nil,func()error{return nil});if err!=nil{t.Fatal(err)}
 lease,err:=owner.Acquire();if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){lease.Release();owner.Seal()})
 c:=&runtimeCoordinator{resources:[]*runtimeResource{{id:id,owner:owner}}}
 writes:=0;write:=func(time.Time)error{writes++;return nil}
 if err:=c.writeRuntimeClock(context.Background(),id,time.Time{},write);err==nil{t.Fatal("unowned write admitted")}
 ctx:=adapter.ContextWithRuntimeResourceLease(context.Background(),lease)
 if err:=c.writeRuntimeClock(ctx,id,time.Time{},write);err!=nil{t.Fatal(err)}
 c.access.Lock();c.resources=nil;c.access.Unlock()
 if err:=c.writeRuntimeClock(ctx,id,time.Time{},write);err==nil{t.Fatal("retired allocation wrote system time")}
 if writes!=1{t.Fatal("wrong native-write count",writes)}
}
