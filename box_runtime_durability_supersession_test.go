package box

import (
 "context"
 "errors"
 "testing"
)

func TestRuntimeLaterCommitCanSupersedeFailedDurableTail(t *testing.T) {
 f:=newRuntimeTestFixture(t,runtimeTestConfig(1080,"first.example"),nil)
 attempts:=0
 if err:=f.box.BindRuntimePersistence(func(identity RuntimeIdentity, content []byte) error {
  attempts++
  if attempts==1{return errors.New("durable backend unavailable")}
  if identity.EffectiveDigest!=runtimeDigest(content){t.Error("persistence content and identity differ")}
  return nil
 });err!=nil{t.Fatal(err)}
 f.start(t)
 _,firstRequest:=f.plan(t,runtimeTestConfig(1080,"second.example"))
 first,err:=f.box.applyRuntimeConfig(context.Background(),"actor-a",firstRequest)
 if err!=nil{t.Fatal(err)}
 if first.State!="COMMITTED_DURABILITY_PENDING"||first.Durable{t.Fatal("failed persistence lost active pending state")}
 _,secondRequest:=f.plan(t,runtimeTestConfig(1080,"third.example"))
 second,err:=f.box.applyRuntimeConfig(context.Background(),"actor-a",secondRequest)
 if err!=nil{t.Fatal(err)}
 if second.State!="COMMITTED"||!second.Durable||second.Before!=first.Active{t.Fatal("later exact revision did not complete its own durable tail")}
 f.box.runtime.access.Lock()
 old:=cloneRuntimeOperation(*f.box.runtime.plans[firstRequest.TransactionID].operation)
 durable:=f.box.runtime.durableIdentity
 f.box.runtime.access.Unlock()
 if old.State!="COMMITTED_DURABILITY_PENDING"||old.Durable{t.Fatal("later acknowledgement rewrote older transaction history")}
 if durable!=second.Active{t.Fatal("durable identity does not identify the acknowledged revision")}
}
