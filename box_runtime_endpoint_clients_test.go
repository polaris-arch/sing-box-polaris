package box

import (
 "context"
 "errors"
 "reflect"
 "testing"

 "github.com/sagernet/sing-box/adapter"
)

type runtimeClientEndpointFixture struct {
 adapter.Endpoint
 events *[]string
 name string
 stageErr error
 validateErr error
}
func (f *runtimeClientEndpointFixture) RuntimeValidate() error { *f.events=append(*f.events,f.name+":validate");return f.validateErr }
func (f *runtimeClientEndpointFixture) RuntimeReservePhysical(context.Context) error { *f.events=append(*f.events,f.name+":reserve");return nil }
func (f *runtimeClientEndpointFixture) RuntimeStagePhysical(context.Context) error { *f.events=append(*f.events,f.name+":stage");return f.stageErr }
func (f *runtimeClientEndpointFixture) RuntimeReleasePhysicalReservation(context.Context) error { *f.events=append(*f.events,f.name+":release");return nil }
func (f *runtimeClientEndpointFixture) RuntimeCloseAndWait() error { *f.events=append(*f.events,f.name+":close");return nil }
func (f *runtimeClientEndpointFixture) RuntimePreparePublication() (func(),error) { *f.events=append(*f.events,f.name+":prepare");return func(){*f.events=append(*f.events,f.name+":publish")},nil }

func TestRuntimeClientEndpointStageFailureCompensatesWithoutPublishing(t *testing.T) {
 var events []string
 a:=&runtimeClientEndpointFixture{events:&events,name:"a"}
 b:=&runtimeClientEndpointFixture{events:&events,name:"b",stageErr:errors.New("stage failed")}
 tx:=runtimeClientEndpointTransaction{next:[]runtimePreparedClientEndpoint{a,b}}
 if tx.stage(context.Background())==nil {t.Fatal("expected stage failure")}
 if len(tx.publish)!=0 {t.Fatal("failed stage published callbacks")}
 if err:=tx.compensate(context.Background());err!=nil{t.Fatal(err)}
 expected:=[]string{"a:validate","b:validate","a:reserve","b:reserve","a:stage","b:stage","b:close","a:close","b:release","a:release"}
 if !reflect.DeepEqual(events,expected){t.Fatalf("events %v",events)}
}
func TestRuntimeClientEndpointPublicationIsExplicit(t *testing.T) {
 var events []string
 a:=&runtimeClientEndpointFixture{events:&events,name:"a"}
 tx:=runtimeClientEndpointTransaction{next:[]runtimePreparedClientEndpoint{a}}
 if err:=tx.stage(context.Background());err!=nil{t.Fatal(err)}
 if err:=tx.preparePublication();err!=nil{t.Fatal(err)}
 if events[len(events)-1]!="a:prepare"{t.Fatal("published during preparation")}
 tx.publish[0]()
 if events[len(events)-1]!="a:publish"{t.Fatal("missing explicit publication")}
}
