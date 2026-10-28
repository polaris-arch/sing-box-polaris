package box

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/service"
)

func TestRuntimeBoxHistoryFollowsActualPublicationAndBorrowedIncarnation(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	root := service.PtrFromContext[urltest.HistoryStorage](f.box.runtime.ctx)
	if root == nil {
		t.Fatal("stable root history missing")
	}
	if probe, connected, err := f.box.AcquireRuntimeURLTest(context.Background(), "a"); !connected || err == nil {
		if probe != nil {
			probe.Release()
		}
		t.Fatal("initial unpublished graph admitted a history writer")
	}
	if root.LoadURLTestHistory("a") != nil {
		t.Fatal("candidate history was visible before startup")
	}
	f.start(t)
	oldLease, oldView := f.acquire(t)
	oldA, oldID, ok := oldView.RuntimeURLTestHistory("a")
	if !ok {
		t.Fatal("actual plain outbound lacks incarnation history")
	}
	oldB, oldBID, ok := oldView.RuntimeURLTestHistory("b")
	if !ok {
		t.Fatal("unchanged plain outbound lacks history")
	}
	oldSelect, _, ok := oldView.RuntimeURLTestHistory("select")
	if !ok {
		t.Fatal("selector private history missing")
	}
	oldProbe, connected, err := f.box.AcquireRuntimeURLTest(context.Background(), "a")
	if !connected || err != nil {
		t.Fatal(err)
	}
	defer oldProbe.Release()
	if oldProbe.Outbound() != f.object(t, "a", 0) || oldProbe.History() != oldA {
		t.Fatal("manual admission returned tag facade or unrelated history")
	}
	if !urltest.PublishRuntimeResult(oldProbe.Context(), oldProbe.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(1, 0), Delay: 10}) {
		t.Fatal("admitted actual writer failed")
	}
	if oldA.LoadURLTestHistory("a") == nil || oldSelect.LoadURLTestHistory("a") == nil || oldB.LoadURLTestHistory("a") != nil {
		t.Fatal("history fanout did not follow captured group consumers")
	}
	consumers := oldView.RuntimeURLTestConsumers("a")
	consumers[0] = nil
	if oldView.RuntimeURLTestConsumers("a")[0] == nil {
		t.Fatal("history consumer slice aliases immutable graph")
	}
	if got := root.LoadURLTestHistory("a"); got == nil || got.Delay != 10 {
		t.Fatal("root projection missed current actual value")
	}
	_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != 2 {
		t.Fatalf("actual Apply failed: %+v %v", operation, err)
	}
	newLease, newView := f.acquire(t)
	newA, newID, _ := newView.RuntimeURLTestHistory("a")
	newB, newBID, _ := newView.RuntimeURLTestHistory("b")
	if newID == oldID || newA == oldA {
		t.Fatal("changed same-tag resource aliased old history")
	}
	if newBID != oldBID || newB != oldB {
		t.Fatal("borrowed unchanged resource did not retain history identity")
	}
	if root.LoadURLTestHistory("a") != nil {
		t.Fatal("replacement inherited old-tag result")
	}
	newA.StoreIfCurrent(newA.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(2, 0), Delay: 20})
	oldResource := runtimeTestResource(t, f, oldID)
	runtimeTestWait(t, oldResource.owner.Retiring(), "old history receiver seal")
	oldLease.Release()
	if !urltest.PublishRuntimeResult(oldProbe.Context(), oldProbe.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(3, 0), Delay: 99}) {
		t.Fatal("live retired invocation could not complete privately")
	}
	if got := root.LoadURLTestHistory("a"); got == nil || got.Delay != 20 {
		t.Fatal("late old probe poisoned new same-tag visible history")
	}
	if oldProbe.IsCurrent() {
		t.Fatal("manual current check accepted same tag with different owner")
	}
	select {
	case <-oldResource.owner.Closed():
		t.Fatal("manual probe did not retain its graph closure")
	default:
	}
	oldProbe.Release()
	if err := oldResource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	newLease.Release()
}

func TestRuntimeHistoryFailedPrepareKeepsPublishedAuthority(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	root := service.PtrFromContext[urltest.HistoryStorage](f.box.runtime.ctx)
	probe, connected, err := f.box.AcquireRuntimeURLTest(context.Background(), "a")
	if !connected || err != nil {
		t.Fatal(err)
	}
	defer probe.Release()
	urltest.PublishRuntimeResult(probe.Context(), probe.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(1, 0), Delay: 10})
	before := f.identity()
	var candidate *urltest.HistoryStorage
	f.setConstructorHook(func(outbound *runtimeTestSocks) error {
		if outbound.Tag() != "a" {
			return nil
		}
		candidate = service.PtrFromContext[urltest.HistoryStorage](outbound.ctx)
		if candidate == nil || candidate == root || candidate == probe.History() {
			return errors.New("candidate has no private history")
		}
		candidate.StoreIfCurrent(candidate.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(2, 0), Delay: 99})
		if got := root.LoadURLTestHistory("a"); got == nil || got.Delay != 10 {
			t.Error("unpublished candidate changed visible history")
		}
		return errors.New("injected actual constructor failure")
	})
	_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.State != "ABORTING_UNAPPLIED" {
		t.Fatalf("unexpected prepare result: %+v %v", operation, err)
	}
	if candidate == nil || f.identity() != before || !probe.IsCurrent() {
		t.Fatal("failed candidate displaced current history authority")
	}
	if got := root.LoadURLTestHistory("a"); got == nil || got.Delay != 10 {
		t.Fatal("abort erased old current history")
	}
}
