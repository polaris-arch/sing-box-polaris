package vmess

import (
 "sync/atomic"
 "testing"
 "time"
)

func TestRuntimeVMessLegacyClockTailIsFenced(t *testing.T){
 f:=newIngressFixture();construction,scope:=ingressConstruction(f)
 closed:=make(chan struct{})
 state,err:=newInboundRuntime(construction,func()error{close(closed);return nil});if err!=nil{t.Fatal(err)}
 entered,proceed,returned:=make(chan struct{}),make(chan struct{}),make(chan struct{})
 var calls atomic.Int64
 clock:=state.wrapTime(func()time.Time{calls.Add(1);close(entered);<-proceed;return time.Unix(1,0)})
 go func(){_ = clock();close(returned)}();ingressWait(t,entered)
 done:=make(chan struct{});go func(){_ = scope.Close();close(done)}();ingressWait(t,closed);ingressPending(t,done)
 close(proceed);ingressWait(t,returned);ingressWait(t,done)
 _ = clock()
 if calls.Load()!=1{t.Fatal("late private ticker callback reached retired clock provider")}
}
