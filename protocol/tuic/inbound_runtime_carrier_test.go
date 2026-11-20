package tuic

import (
	"testing"

	"github.com/sagernet/sing-box/internal/runtimeingresstest"
)

func newHandshakeCarrierFixture(t *testing.T) runtimeingresstest.CarrierFixture {
	t.Helper()
	f := newIngressFixture()
	construction, scope := ingressConstruction(f)
	t.Cleanup(func() { _ = scope.Close() })
	state, err := newInboundRuntime(construction, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, graph := f.context()
	return runtimeingresstest.CarrierFixture{
		Context:    ctx,
		Wrap:       state.wrapConnection,
		Release:    graph.Release,
		Graphs:     &f.graphs,
		CloseOwner: state.closeAndWait,
	}
}

func TestRuntimeProtocolHandshakeIsJoinedBeforeCarrierRelease(t *testing.T) {
	runtimeingresstest.CheckHandshakeJoinsBeforeRelease(t, newHandshakeCarrierFixture(t))
}

func TestRuntimeProtocolHandshakePanicRetainsUncertainty(t *testing.T) {
	runtimeingresstest.CheckHandshakePanicRetainsUncertainty(t, newHandshakeCarrierFixture(t))
}
