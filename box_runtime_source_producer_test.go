package box

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runtimeTestLocalConfig(path string) []byte {
	inline := `{"type":"inline","tag":"sites","rules":[{"domain_suffix":["example.org"]}]}`
	local := fmt.Sprintf(`{"type":"local","tag":"sites","format":"source","path":%q}`, path)
	return []byte(strings.Replace(string(runtimeTestConfig(1080, "example.org")), inline, local, 1))
}
func runtimeTestSourceBytes(domain string) []byte { return []byte(fmt.Sprintf(`{"version":3,"rules":[{"domain_suffix":[%q]}]}`, domain)) }
func runtimeTestProducer(t *testing.T, f *runtimeTestFixture) *runtimeSourceProducer {
	t.Helper()
	f.box.runtime.access.Lock(); defer f.box.runtime.access.Unlock()
	for _, resource := range f.box.runtime.resources { if resource.sourceProducer != nil { return resource.sourceProducer } }
	t.Fatal("actual source producer missing"); return nil
}

func TestRuntimeLocalProducerPublishesNewImmutableClosure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	if err := os.WriteFile(path, runtimeTestSourceBytes("example.org"), 0600); err != nil { t.Fatal(err) }
	f := newRuntimeTestFixture(t, runtimeTestLocalConfig(path), nil)
	committed := make(chan RuntimeIdentity, 8)
	if err := f.box.BindRuntimePersistence(func(id RuntimeIdentity, _ []byte) error { committed <- id; return nil }); err != nil { t.Fatal(err) }
	f.start(t)
	old, oldView := f.acquire(t)
	producer := runtimeTestProducer(t, f)
	if err := os.WriteFile(path, runtimeTestSourceBytes("new.example"), 0600); err != nil { t.Fatal(err) }
	// Signal the production callback path explicitly; event delivery timing from
	// the OS is not an ordering premise. The bounded queue coalesces both events.
	producer.signal()
	select {
	case id := <-committed:
		if id.Revision != 2 { t.Fatalf("source publication revision: %+v", id) }
	case <-runtimeTestContext(t).Done(): t.Fatal("source transaction did not commit")
	}
	_, next := f.acquire(t)
	if next.componentIDs["rule-set:sites"] == oldView.componentIDs["rule-set:sites"] { t.Fatal("mutated old source instead of replacing its owner") }
	if next.componentIDs["outbound:a"] != oldView.componentIDs["outbound:a"] { t.Fatal("source-only update rebuilt independent outbound") }
	if runtimeTestProducer(t, f) != producer { t.Fatal("unchanged watcher identity was rebuilt") }
	if old.View().Identity().Revision != 1 { t.Fatal("old reader changed generation") }
	old.Release()
}

func TestRuntimeLocalSourceChangedAfterPlanPreservesCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	if err := os.WriteFile(path, runtimeTestSourceBytes("example.org"), 0600); err != nil { t.Fatal(err) }
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil); f.start(t)
	_, request := f.plan(t, runtimeTestLocalConfig(path))
	if err := os.WriteFile(path, runtimeTestSourceBytes("changed.example"), 0600); err != nil { t.Fatal(err) }
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil { t.Fatal(err) }
	if operation.State != "ABORTING_UNAPPLIED" || f.identity() != request.Expected { t.Fatalf("stale source published: %+v", operation) }
}

func TestRuntimeSourceSignalCoalescesAndStopsAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &runtimeSourceProducer{ctx:ctx, cancel:cancel, changed:make(chan struct{}, 1)}
	for range 100 { p.signal() }
	if len(p.changed) != 1 { t.Fatal("source notification backlog is not bounded") }
	<-p.changed; p.stop(); p.signal()
	if len(p.changed) != 0 { t.Fatal("stopped producer admitted work") }
}

func TestRuntimeSameConfigLocalContentChangeIsNotNoOp(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"sites.json")
 if err:=os.WriteFile(path,runtimeTestSourceBytes("example.org"),0600);err!=nil{t.Fatal(err)}
 config:=runtimeTestLocalConfig(path)
 f:=newRuntimeTestFixture(t,config,nil);f.start(t)
 // Isolate manual Plan from OS notification timing; both use the same snapshot path.
 runtimeTestProducer(t,f).stop()
 if err:=os.WriteFile(path,runtimeTestSourceBytes("replacement.example"),0600);err!=nil{t.Fatal(err)}
 plan,_:=f.plan(t,config)
 if plan.NoOp{t.Fatal("identical config bytes hid changed local resource content")}
}

func TestRuntimeNoOpLocalSourceDriftDoesNotCommit(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"sites.json")
 if err:=os.WriteFile(path,runtimeTestSourceBytes("example.org"),0600);err!=nil{t.Fatal(err)}
 config:=runtimeTestLocalConfig(path)
 f:=newRuntimeTestFixture(t,config,nil);f.start(t)
 runtimeTestProducer(t,f).stop()
 plan,request:=f.plan(t,config)
 if !plan.NoOp{t.Fatal("unchanged source should permit configuration-only no-op")}
 if err:=os.WriteFile(path,runtimeTestSourceBytes("drift.example"),0600);err!=nil{t.Fatal(err)}
 before:=f.identity()
 _,err:=f.box.applyRuntimeConfig(context.Background(),"actor-a",request)
 if err==nil{t.Fatal("source drift accepted a stale no-op receipt")}
 if f.identity()!=before{t.Fatal("failed no-op changed active identity")}
}
