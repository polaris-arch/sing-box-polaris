package hysteria2

import (
 "context"
 "testing"
 "time"
)

func TestClientRuntimeJoinsActualWorkerAndRejectsNewWork(t *testing.T){
 c:=&Client{ctx:context.Background()};c.initRuntime()
 entered,release,closed:=make(chan struct{}),make(chan struct{}),make(chan struct{})
 if !c.runtime.run(func(){close(entered);<-release}){t.Fatal("initial admission rejected")}
 <-entered
 go func(){_ = c.RuntimeCloseAndWait();close(closed)}()
 select{case <-c.ctx.Done():case <-time.After(5*time.Second):t.Fatal("close did not cancel client lifetime")}
 select{case <-closed:t.Fatal("close certified an unfinished worker");default:}
 if c.runtime.run(func(){t.Error("sealed worker was dispatched")}){t.Fatal("sealed admission accepted")}
 close(release)
 select{case <-closed:case <-time.After(5*time.Second):t.Fatal("actual worker completion was not joined")}
 if _,err:=c.offer(context.Background());err==nil{t.Fatal("terminal client reused")}
 if err:=c.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
}
func TestClientRuntimeCancelsPendingOfferBeforeJoin(t *testing.T){
 c:=&Client{ctx:context.Background()};c.initRuntime()
 ctx,cancel:=context.WithCancelCause(c.ctx)
 c.pending=&clientOffer{done:make(chan struct{}),cancel:cancel}
 left:=make(chan struct{})
 if !c.runtime.run(func(){<-ctx.Done();close(left)}){t.Fatal("admission")}
 if err:=c.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
 select{case <-left:default:t.Fatal("pending offer was not joined")}
 if !c.pending.discarded{t.Fatal("late pending offer may publish")}
}
