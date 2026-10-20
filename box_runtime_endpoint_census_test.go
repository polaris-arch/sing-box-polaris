package box

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
)

func TestEndpointCensusPrunesOnlySuccessfulActualCompletion(t *testing.T) {
	failure := errors.New("native cleanup uncertain")
	c := &runtimeCoordinator{catalog: make(map[adapter.RuntimeResourceID]*runtimeResource)}
	for index, cleanupErr := range []error{nil, failure} {
		id := adapter.RuntimeResourceID{Incarnation: "endpoint-census", Sequence: uint64(index + 1)}
		owner, err := runtimegraph.NewResourceOwner(context.Background(), id, nil, func() error { return cleanupErr })
		if err != nil {
			t.Fatal(err)
		}
		lease, err := owner.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		c.catalog[id] = &runtimeResource{id: id, owner: owner, networkReady: true}
		owner.Seal()
		c.pruneRuntimeCatalogLocked()
		if c.catalog[id] == nil {
			t.Fatal("retained endpoint removed before actual close")
		}
		lease.Release()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		err = owner.WaitClosed(ctx)
		cancel()
		if cleanupErr == nil && err != nil {
			t.Fatal(err)
		}
		if cleanupErr != nil && err == nil {
			t.Fatal("cleanup failure lost")
		}
		c.pruneRuntimeCatalogLocked()
		if (c.catalog[id] != nil) != (cleanupErr != nil) {
			t.Fatal("completion success/error census distinction lost")
		}
	}
}
