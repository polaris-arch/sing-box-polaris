package box

import (
	stdjson "encoding/json"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

// This is the R4 regeneration fixture's real construction/binding. Only its
// background worker activation is held with the existing fixture helper, so
// tests can order normal producer.refresh calls without racing OS delivery.
// The watcher, source snapshots, planner, Apply and all graph owners are real.
func r5PublicationControlFixture(t *testing.T, path string, calls *atomic.Int32, mode bool) *runtimeTestFixture {
	t.Helper()
	config := runtimeTestLocalConfig(path)
	if mode {
		var root, dns map[string]stdjson.RawMessage
		if err := stdjson.Unmarshal(config, &root); err != nil {
			t.Fatal(err)
		}
		if err := stdjson.Unmarshal(root["dns"], &dns); err != nil {
			t.Fatal(err)
		}
		// Actual emitted rules supply Rule/Global availability through the
		// production CalculateModeList, rather than assigning a private list.
		dns["rules"] = []byte("[{\"clash_mode\":\"Rule\",\"action\":\"route\",\"server\":\"resolver\"},{\"clash_mode\":\"Global\",\"action\":\"route\",\"server\":\"resolver\"}]")
		var err error
		root["dns"], err = stdjson.Marshal(dns)
		if err != nil {
			t.Fatal(err)
		}
		config, err = stdjson.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
	}
	config = r3SourceCanaryConfig(t, config)
	return r3SourceFixture(t, config, nil, nil, false, func(f *runtimeTestFixture) {
		if err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error {
			calls.Add(1)
			return &RuntimeOwnerAcknowledgementRequiredError{Mode: "app_authoritative_regeneration"}
		}, "app_authoritative_regeneration", false); err != nil {
			t.Fatal(err)
		}
		r3SourceHoldWorkerActivation(t, f)
	})
}

func r5PublicationRequireUnknown(t *testing.T, f *runtimeTestFixture, calls *atomic.Int32) {
	t.Helper()
	status, err := f.box.GetRuntimeConfigStatus("actor-a", "", "")
	if err != nil || status.PersistenceMode != "app_authoritative_regeneration" ||
		status.DurableAppliedDigest != "" || status.DurableDesiredStateDigest != "" ||
		status.DurableDesiredStateRevision != "" || status.DurableOwnerReloadAcknowledged || calls.Load() != 0 {
		t.Fatalf("resource/control update manufactured native reload or App durability: %+v / %v / calls=%d", status, err, calls.Load())
	}
}

// The DNS router actually depends on the captured rule-set source. A changed
// source replaces that resource, whose existing StopRuntimeProducers callback
// runs in Apply's postpublication retirement loop. Wrap that real callback
// during quiescent fixture setup: preserve its complete behavior first, then
// hold the outer Apply tail. No production hook, identity, lineage or receipt
// is injected, and no synthetic resource is added to force a retirement.
func TestRuntimeSourcePublicationSettlesBeforeConcurrentManagementControl(t *testing.T) {
	for _, warm := range []bool{false, true} {
		for _, control := range []string{"selector", "mode"} {
			t.Run(fmt.Sprintf("prior-source-child=%t/%s", warm, control), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "sites.json")
				r3SourceWrite(t, path, runtimeTestSourceBytes("initial.example"))
				var calls atomic.Int32
				f := r5PublicationControlFixture(t, path, &calls, control == "mode")
				producer := runtimeTestProducer(t, f)
				if warm {
					r3SourceWrite(t, path, runtimeTestSourceBytes("warm.example"))
					if wait, retry := producer.refresh(); wait != nil || retry {
						t.Fatal("real initial source refresh did not settle before the race")
					}
					r4SourceAtRevision(t, f, 2)
				}
				before := f.identity()
				canonical := r3SourceCanonical(f)
				r5PublicationRequireUnknown(t, f, &calls)
				oldLease, oldView := f.acquire(t)
				oldDNS := runtimeTestResource(t, f, oldView.componentIDs["dns-router"])
				if oldDNS.stop == nil {
					t.Fatal("actual DNS resource lacks its real producer stop callback")
				}
				barrier := newRuntimeTestBarrier()
				t.Cleanup(barrier.open)
				originalStop := oldDNS.stop
				oldDNS.stop = func() {
					originalStop()
					barrier.block()
				}
				type refreshResult struct {
					wait  <-chan struct{}
					retry bool
				}
				finished := make(chan refreshResult, 1)
				r3SourceWrite(t, path, runtimeTestSourceBytes("racing.example"))
				go func() {
					wait, retry := producer.refresh()
					finished <- refreshResult{wait, retry}
				}()
				runtimeTestWait(t, barrier.entered, "real retired DNS stop after graph publication")
				_, currentView := f.acquire(t)
				c := f.box.runtime
				c.access.Lock()
				published, preparing := c.active, c.preparing
				var record *runtimePlanRecord
				for _, candidate := range c.plans {
					if candidate.sourceProof != nil && candidate.operation != nil && candidate.operation.Active == published {
						record = candidate
						break
					}
				}
				c.access.Unlock()
				if !preparing || published.Incarnation != before.Incarnation ||
					published.Revision != before.Revision+1 || published.ControlRevision != before.ControlRevision ||
					published.EffectiveDigest != before.EffectiveDigest || record == nil ||
					currentView.componentIDs["dns-router"] == oldView.componentIDs["dns-router"] {
					t.Fatal("barrier was not the actual published-but-preparing source retirement window", before, published)
				}
				select {
				case <-finished:
					t.Fatal("outer source Apply returned before the real retirement barrier released")
				default:
				}
				// Match actual management ingress: invoke the real controller on
				// the currently published selector owner, or the real mode manager.
				controlled := make(chan bool, 1)
				go func() {
					if control == "selector" {
						controlled <- c.SelectRuntimeOutbound(currentView.componentIDs["outbound:select"], "select", "b")
					} else {
						controlled <- c.SetRuntimeClashMode("Global")
					}
				}()
				var accepted bool
				select {
				case accepted = <-controlled:
				case <-runtimeTestContext(t).Done():
					t.Fatal("real management control did not complete while outer Apply remained preparing")
				}
				afterControl := f.identity()
				if !accepted || afterControl.Incarnation != published.Incarnation ||
					afterControl.Revision != published.Revision || afterControl.EffectiveDigest != published.EffectiveDigest ||
					afterControl.ControlRevision != published.ControlRevision+1 {
					t.Fatal("actual management control did not independently advance its full identity", accepted, published, afterControl)
				}
				c.access.Lock()
				// Original source receipt keeps its publication identity; the
				// subsequent control must not be rebound into that operation.
				settled := c.preparing && c.sourceLineage != nil && c.sourceLineage.current == published &&
					record.operation.Active == published && record.operation.Before == before &&
					record.operation.State == "COMMITTED" && record.operation.PersistenceMode == runtimeSourceOnlyMode &&
					len(record.operation.Errors) == 1 && record.operation.Errors[0].Code == "BASE_CONFIGURATION_DURABILITY_UNPROVEN" &&
					!record.operation.Durable && !record.operation.OwnerReloadAcknowledged &&
					!record.persistenceTailEntered && !record.awaitingOwnerAcknowledgement &&
					c.configurationOwner == nil && c.pendingPersistence == nil && c.sourceDriver == nil
				c.access.Unlock()
				if !settled {
					t.Fatal("published source receipt/lineage was not settled before a real concurrent control")
				}
				if control == "selector" {
					selected, ok := currentView.outbounds.Outbound("select")
					group, selectable := selected.(adapter.OutboundGroup)
					if !ok || !selectable || group.Selected("tcp") == nil || group.Selected("tcp").Tag() != "b" {
						t.Fatal("real selector did not retain the accepted management choice")
					}
				} else if c.clashMode.Mode() != "Global" {
					t.Fatal("real clash-mode manager did not accept the emitted Global variant")
				}
				r5PublicationRequireUnknown(t, f, &calls)
				barrier.open()
				select {
				case result := <-finished:
					if result.wait != nil || result.retry {
						t.Fatal("actual source refresh failed after its publication/control race")
					}
				case <-runtimeTestContext(t).Done():
					t.Fatal("actual source Apply did not finish after original stop was released")
				}
				if f.identity() != afterControl {
					t.Fatal("late source tail overwrote the completed management control")
				}
				c.access.Lock()
				retained := record.operation.Active == published && record.operation.State == "COMMITTED" &&
					record.operation.PersistenceMode == runtimeSourceOnlyMode &&
					len(record.operation.Errors) == 1 && record.operation.Errors[0].Code == "BASE_CONFIGURATION_DURABILITY_UNPROVEN" &&
					c.sourceLineage != nil && c.sourceLineage.current == published &&
					c.configurationOwner == nil && c.pendingPersistence == nil
				c.access.Unlock()
				if !retained {
					t.Fatal("late retirement tail changed the already settled source receipt/lineage")
				}
				// No NoOp, App ACK, retry-driver call or manual settlement is used
				// to recover the child. Another real source edit must progress
				// immediately through the same original production producer path.
				r3SourceWrite(t, path, runtimeTestSourceBytes("following.example"))
				nextProducer := runtimeTestProducer(t, f)
				if wait, retry := nextProducer.refresh(); wait != nil || retry {
					t.Fatal("next real source refresh remained deferred behind the raced child")
				}
				next := f.identity()
				if next.Incarnation != afterControl.Incarnation || next.Revision != afterControl.Revision+1 ||
					next.ControlRevision != afterControl.ControlRevision || next.EffectiveDigest != afterControl.EffectiveDigest {
					t.Fatal("next source publication lost the actual control/configuration lineage", afterControl, next)
				}
				nextRecord := r4SourceAtRevision(t, f, next.Revision)
				c.access.Lock()
				continued := nextRecord.operation.Before == afterControl && nextRecord.operation.Active == next &&
					nextRecord.operation.State == "COMMITTED" && nextRecord.operation.PersistenceMode == runtimeSourceOnlyMode &&
					len(nextRecord.operation.Errors) == 1 && nextRecord.operation.Errors[0].Code == "BASE_CONFIGURATION_DURABILITY_UNPROVEN" &&
					!nextRecord.operation.Durable && !nextRecord.operation.OwnerReloadAcknowledged &&
					!nextRecord.persistenceTailEntered && !nextRecord.awaitingOwnerAcknowledgement &&
					c.pendingPersistence == nil && c.configurationOwner == nil &&
					c.sourceLineage != nil && c.sourceLineage.current == next
				c.access.Unlock()
				if !continued || string(r3SourceCanonical(f)) != string(canonical) {
					t.Fatal("following actual source event did not retain clean UNKNOWN resource-only lineage")
				}
				_, nextView := f.acquire(t)
				set, found := nextView.router.RuleSet("sites")
				if !found || !set.Match(&adapter.InboundContext{Domain: "following.example"}) ||
					set.Match(&adapter.InboundContext{Domain: "racing.example"}) {
					t.Fatal("next revision did not contain the actual new immutable source predicate")
				}
				oldSet, found := oldView.router.RuleSet("sites")
				oldDomain := "initial.example"
				if warm {
					oldDomain = "warm.example"
				}
				if !found || !oldSet.Match(&adapter.InboundContext{Domain: oldDomain}) ||
					oldSet.Match(&adapter.InboundContext{Domain: "following.example"}) {
					t.Fatal("source/control race mutated the retained original graph")
				}
				if control == "selector" {
					selected, ok := nextView.outbounds.Outbound("select")
					group, selectable := selected.(adapter.OutboundGroup)
					if !ok || !selectable || group.Selected("tcp") == nil || group.Selected("tcp").Tag() != "b" {
						t.Fatal("following source revision lost the real management selection")
					}
				} else if c.clashMode.Mode() != "Global" {
					t.Fatal("following source revision lost the real management mode")
				}
				r5PublicationRequireUnknown(t, f, &calls)
				oldLease.Release()
			})
		}
	}
}
