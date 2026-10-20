package box

import (
 "context"
 "errors"
 "reflect"
 "testing"

 "github.com/sagernet/sing-box/adapter"
)

type runtimeCertificateEffectFixture struct {
 name string
 events *[]string
 external bool
 stageError error
 compensationError error
 compensationPanic bool
}
func(f *runtimeCertificateEffectFixture)StageRuntime(context.Context)error{*f.events=append(*f.events,"stage:"+f.name);return f.stageError}
func(f *runtimeCertificateEffectFixture)CompensateRuntime()error{*f.events=append(*f.events,"compensate:"+f.name);if f.compensationPanic{panic("fixture")};return f.compensationError}
func(f *runtimeCertificateEffectFixture)RuntimeExternalEffects()bool{return f.external}
func(f *runtimeCertificateEffectFixture)RuntimeActivate(){*f.events=append(*f.events,"activate:"+f.name)}
func(f *runtimeCertificateEffectFixture)RuntimeStop(){}
func TestRuntimeCertificateFailedStageKeepsEffectEvidence(t *testing.T){
 var events []string
 failure:=errors.New("issuance failed after possible external write")
 first:=&runtimeCertificateEffectFixture{name:"first",events:&events}
 failed:=&runtimeCertificateEffectFixture{name:"failed",events:&events,external:true,stageError:failure}
 never:=&runtimeCertificateEffectFixture{name:"never",events:&events}
 graph:=&preparedRuntimeGraph{inlineEffects:[]adapter.RuntimeStagedEffect{first,failed,never}}
 if err:=graph.stageRuntimeCertificates(context.Background());!errors.Is(err,failure){t.Fatalf("stage: %v",err)}
 if !graph.externalEffectsAttempted{t.Fatal("lost external effect evidence")}
 graph.compensateRuntimeCertificates()
 want:=[]string{"stage:first","stage:failed","compensate:failed","compensate:first"}
 if !reflect.DeepEqual(events,want){t.Fatalf("events: %v",events)}
}
func TestRuntimeCertificateCompensationPanicDoesNotSkipEarlierEffect(t *testing.T){
 var events []string
 first:=&runtimeCertificateEffectFixture{name:"first",events:&events}
 panics:=&runtimeCertificateEffectFixture{name:"panic",events:&events,compensationPanic:true}
 graph:=&preparedRuntimeGraph{stagedProviders:[]adapter.RuntimeStagedEffect{first,panics}}
 graph.compensateRuntimeCertificates()
 if graph.compensationError==nil{t.Fatal("panic must retain uncertainty")}
 if !reflect.DeepEqual(events,[]string{"compensate:panic","compensate:first"}){t.Fatalf("events: %v",events)}
}
func TestRuntimeCertificateCancellationBeforeEffect(t *testing.T){
 var events []string
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 graph:=&preparedRuntimeGraph{inlineEffects:[]adapter.RuntimeStagedEffect{&runtimeCertificateEffectFixture{name:"first",events:&events,external:true}}}
 if !errors.Is(graph.stageRuntimeCertificates(ctx),context.Canceled){t.Fatal("missing cancellation")}
 if len(events)!=0||graph.externalEffectsAttempted{t.Fatal("canceled preparation admitted an effect")}
}
