package runtimegraph

import "testing"

func TestGraphObservationCannotMissPublicationOrSeal(t *testing.T) {
	store := testStore(t)
	first := testGraph(t, 1)
	publishTestGraph(t, store, 0, first)
	lease, changed, err := store.AcquireWithChanges()
	if err != nil || lease.View().Identity().Revision != 1 {
		t.Fatal("current graph observation failed")
	}
	second := testGraph(t, 2)
	publishTestGraph(t, store, 1, second)
	select {
	case <-changed:
	default:
		t.Fatal("publication notification lost")
	}
	select {
	case <-first.Drained():
		t.Fatal("observation did not retain the old view")
	default:
	}
	lease.Release()
	await(t, first.Drained())
	lease, changed, err = store.AcquireWithChanges()
	if err != nil || lease.View().Identity().Revision != 2 {
		t.Fatal("replacement observation is stale")
	}
	store.Seal()
	select {
	case <-changed:
	default:
		t.Fatal("seal did not wake API observers")
	}
	lease.Release()
	await(t, store.Drained())
}
