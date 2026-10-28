package shadowsocks

import (
	"context"
	"testing"
)

type runtimeRelayAuthFixture struct{}

func TestRuntimeShadowsocksPacketBindingKeepsAuthenticationAndExactLineage(t *testing.T) {
	f := newIngressFixture()
	construction, scope := ingressConstruction(f)
	defer scope.Close()
	state, err := newInboundRuntime(construction, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	handler := &runtimeUpstreamHandler{runtime: state}
	incoming, graph := f.context()
	bind, release, err := handler.RetainPacketContext(incoming)
	if err != nil {
		t.Fatal(err)
	}
	graph.Release()
	final := bind(context.WithValue(context.Background(), runtimeRelayAuthFixture{}, "authenticated relay user"))
	if final.Value(runtimeRelayAuthFixture{}) != "authenticated relay user" {
		t.Fatal("lifetime binding discarded relay authentication")
	}
	_, leave, err := state.enter(final)
	if err != nil {
		t.Fatal(err)
	}
	leave()
	release()
	release()
	if f.graphs.Load() != 0 || f.resources.Load() != 0 {
		t.Fatal("session tail leaked exact ownership")
	}
	if _, _, err := state.enter(final); err == nil {
		t.Fatal("terminal session context reopened active graph admission")
	}
}
