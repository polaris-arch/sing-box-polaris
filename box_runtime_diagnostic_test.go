package box

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
)

func TestCleanupDiagnosticSaturationAndFiniteKinds(t *testing.T) {
	for _, n := range []uint64{cleanupDiagnosticCap, cleanupDiagnosticCap + 1, ^uint64(0)} {
		var total uint64
		var clipped bool
		cleanupDiagnosticAdd(&total, n, &clipped)
		if total != cleanupDiagnosticCap || clipped != (n > cleanupDiagnosticCap) {
			t.Fatal(total, clipped)
		}
		cleanupDiagnosticAdd(&total, 1, &clipped)
		if total != cleanupDiagnosticCap || !clipped {
			t.Fatal("overflow")
		}
	}
	budget := 1
	clipped := false
	r := &runtimeResource{kind: "secret-host", components: map[string]*runtimeComponent{"secret-token": {}}}
	if cleanupDiagnosticKind(r, &budget, &clipped) != 0 || budget != 0 || clipped {
		t.Fatal("unknown kind escaped")
	}
	if cleanupDiagnosticKind(r, &budget, &clipped) != 0 || !clipped {
		t.Fatal("component budget missing")
	}
}
func TestCleanupDiagnosticDoesNotExposeIdentityOrWaitForCoordinator(t *testing.T) {
	id := adapter.RuntimeResourceID{Incarnation: "secret-incarnation", Sequence: 17}
	owner, err := runtimegraph.NewResourceOwner(context.Background(), id, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	defer owner.Seal()
	c := &runtimeCoordinator{catalog: map[adapter.RuntimeResourceID]*runtimeResource{id: {kind: "secret-tag", owner: owner}}, shutdownDone: make(chan struct{})}
	s := &Box{runtime: c}
	snapshot := s.RuntimeCleanupSnapshot()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") || !snapshot.Available || snapshot.Resources[0].References != 1 {
		t.Fatal(string(raw))
	}
	c.access.Lock()
	contended := s.RuntimeCleanupSnapshot()
	c.access.Unlock()
	if contended.Available {
		t.Fatal("diagnostic waited for coordinator")
	}
}
