package adapter

import (
 "context"
 "errors"
 "testing"
)

func TestConstructionScopeErrObservesCanceledOwnerWithLiveCaller(t *testing.T) {
 parent,cancel:=context.WithCancel(context.Background())
 scope:=NewScope(parent,nil)
 caller:=ContextWithConstructionScope(context.Background(),scope)
 cancel()
 if caller.Err()!=nil{t.Fatal("fixture caller unexpectedly canceled")}
 if !errors.Is(ConstructionScopeErr(caller),context.Canceled){t.Fatal("canceled constructor owner was hidden")}
 called:=false
 if err:=DeferConstructionCleanup(caller,func()error{called=true;return nil});err!=nil{t.Fatal(err)}
 if !called{t.Fatal("canceled owner did not run cleanup immediately")}
}
func TestConstructionScopeErrDoesNotInventStandaloneScope(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=ConstructionScopeErr(ctx);err!=nil{t.Fatal("standalone caller has no construction scope",err)}
}
