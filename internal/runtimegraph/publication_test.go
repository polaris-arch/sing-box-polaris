package runtimegraph

import (
 "testing"
 "github.com/sagernet/sing-box/adapter"
)

type testPublication struct { publish func() }
func (p *testPublication) Publish() { p.publish() }

func TestPreparedPublicationRejectedWithoutActivation(t *testing.T) {
 store := testStore(t)
 graph := testGraph(t, 1)
 calls := 0
 participant := &testPublication{publish:func(){calls++}}
 if _, err := store.PublishPrepared(adapter.RuntimeRevision{Incarnation:"other"}, graph, participant); err == nil { t.Fatal("invalid expected revision accepted") }
 if calls != 0 { t.Fatal("rejected graph activated candidate state") }
 if _, err := store.PublishPrepared(adapter.RuntimeRevision{Incarnation:"test-run"}, graph, participant); err != nil { t.Fatal(err) }
 if calls != 1 { t.Fatal("candidate state not activated exactly once") }
}

func TestPreparedPublicationVisibleBeforeAdmissionUnlock(t *testing.T) {
 store := testStore(t)
 graph := testGraph(t, 1)
 visible := false
 participant := &testPublication{publish:func(){
  // TryLock observes the real admission guard without blocking or recursively
  // admitting a request from the publication participant.
  if store.admission.mu.TryLock() { store.admission.mu.Unlock(); t.Error("activation ran outside admission guard") }
  visible = true
 }}
 if _, err := store.PublishPrepared(adapter.RuntimeRevision{Incarnation:"test-run"}, graph, participant); err != nil { t.Fatal(err) }
 lease, err := store.Acquire()
 if err != nil { t.Fatal(err) }; defer lease.Release()
 if !visible || lease.View().Identity().Revision != 1 { t.Fatal("published graph without activated state") }
}

func TestPreparedPublicationClaimFailureDoesNotActivate(t *testing.T) {
 first,second:=testStore(t),testStore(t)
 graph:=testGraph(t,1)
 if _,err:=first.Publish(adapter.RuntimeRevision{Incarnation:"test-run"},graph);err!=nil{t.Fatal(err)}
 calls:=0
 participant:=&testPublication{publish:func(){calls++}}
 if _,err:=second.PublishPrepared(adapter.RuntimeRevision{Incarnation:"test-run"},graph,participant);err==nil{t.Fatal("claimed graph republished")}
 if calls!=0{t.Fatal("claim failure opened candidate answers")}
 if lease,err:=second.Acquire();err==nil{lease.Release();t.Fatal("claim failure exposed graph")}
}
