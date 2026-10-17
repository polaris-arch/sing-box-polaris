package daemon

import (
 "context"
 "testing"
 "time"
 "github.com/sagernet/sing/service"
 "github.com/sagernet/sing-box/adapter"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
)
type ruleSetStatusFixture struct { adapter.RuleSet; value adapter.RuleSetLoadStatus }
func (f ruleSetStatusFixture) RuleSetStatus() adapter.RuleSetLoadStatus { return f.value }
func TestRuleSetStatusRequestBounds(t *testing.T) {
 for _, req:=range []*RuleSetStatusRequest{nil, {}, {Tags:[]string{""}}, {Tags:[]string{"a","a"}}, {Tags:make([]string,257)}} {
  if status.Code(validateRuleSetStatusTags(req))!=codes.InvalidArgument {t.Fatal("invalid tags accepted")}
 }
 if err:=validateRuleSetStatusTags(&RuleSetStatusRequest{Tags:[]string{"a"}});err!=nil {t.Fatal(err)}
}
func TestRuleSetStatusPreservesLoadedStateAndInstance(t *testing.T) {
 result,err:=collectRuleSetStatus([]string{"a"},42,func(tag string)(adapter.RuleSet,bool){
  return ruleSetStatusFixture{value:adapter.RuleSetLoadStatus{ActiveDigest:"accepted",Revision:7,WatcherState:"watching",LastError:"failed candidate"}},true
 })
 if err!=nil {t.Fatal(err)}
 if result.InstanceStartedAtUnixNano!=42 || len(result.RuleSets)!=1 || result.RuleSets[0].ActiveDigest!="accepted" || result.RuleSets[0].Revision!=7 || result.RuleSets[0].LastError!="failed candidate" {t.Fatal(result)}
 _,err=collectRuleSetStatus([]string{"missing"},42,func(string)(adapter.RuleSet,bool){return nil,false})
 if status.Code(err)!=codes.NotFound {t.Fatal(err)}
}


type ruleStatusRouterFixture struct {
 adapter.Router
 set adapter.RuleSet
 reads int
}
func (r *ruleStatusRouterFixture) RuleSet(string) (adapter.RuleSet, bool) {
 r.reads++
 return r.set, true
}

func TestRuleSetStatusRejectsReloadGapAfterAdmissionWait(t *testing.T) {
 oldStartedAt := time.Unix(1, 0)
 router := &ruleStatusRouterFixture{set: ruleSetStatusFixture{value: adapter.RuleSetLoadStatus{
  ActiveDigest: "new-instance", Revision: 1, WatcherState: "watching",
 }}}
 ctx := service.ContextWith[adapter.Router](context.Background(), router)
 s := &StartedService{
  serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
  instance: &Instance{ctx: context.Background()},
  startedAt: oldStartedAt,
 }
 // Deterministically reproduce Reload's interleaving: the real admission wait
 // saw STARTED, then Reload published STARTING + replacement instance, but has
 // not completed instance.Start() or replaced the previous startedAt yet.
 if err := s.waitForStarted(context.Background()); err != nil { t.Fatal(err) }
 s.serviceAccess.Lock()
 s.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTING}
 s.instance = &Instance{ctx: ctx}
 s.serviceAccess.Unlock()
 response, err := s.readStartedRuleSetStatus([]string{"a"})
 if status.Code(err) != codes.Unavailable || response != nil { t.Fatalf("half-started instance accepted: %v %v", response, err) }
 if router.reads != 0 { t.Fatal("half-started router was consulted") }
 // Once Reload atomically publishes its final timestamp and STARTED status,
 // the ordinary RPC can return the new identity, never the retained old one.
 newStartedAt := time.Unix(2, 0)
 s.serviceAccess.Lock()
 s.startedAt = newStartedAt
 s.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
 s.serviceAccess.Unlock()
 response, err = s.GetRuleSetStatus(context.Background(), &RuleSetStatusRequest{Tags: []string{"a"}})
 if err != nil { t.Fatal(err) }
 if response.InstanceStartedAtUnixNano != newStartedAt.UnixNano() || response.InstanceStartedAtUnixNano == oldStartedAt.UnixNano() || response.RuleSets[0].ActiveDigest != "new-instance" { t.Fatal(response) }
 if router.reads != 1 { t.Fatal("expected one completed-instance read") }
}
