//go:build with_quic

package runtimeingress

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestQUICPacketAddressViewObservesPhysicalBind(t *testing.T) {
	var actual atomic.Pointer[net.UDPAddr]
	actual.Store(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	// Nil embedded I/O deliberately prevents this address-only fixture from
	// masking an accidental read/write through an unguarded underlying carrier.
	view := &quicPacketAddressView{address: func() net.Addr { return actual.Load() }}
	if view.LocalAddr().(*net.UDPAddr).Port != 0 {
		t.Fatal("unexpected pre-bind port")
	}
	actual.Store(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 44321})
	if view.LocalAddr().(*net.UDPAddr).Port != 44321 {
		t.Fatal("QUIC retained the pre-bind address")
	}
	if _, ok := any(view).(interface{ Upstream() any }); ok {
		t.Fatal("address view leaked raw I/O")
	}
}

type quicServiceContextKey struct{}

func TestSessionContextBorrowsPhysicalLifetimeRatherThanSetupTask(t *testing.T) {
	var forks atomic.Int32
	graph := &fixtureLease{forks: &forks}
	physical := adapter.ContextWithRuntimeLease(context.Background(), graph)
	defer graph.Release()
	physical, cancel := context.WithCancel(physical)
	defer cancel()
	fallback := context.WithValue(context.Background(), quicServiceContextKey{}, "service")
	session, err := quicServerSessionContext(fallback, physical)
	if err != nil {
		t.Fatal(err)
	}
	if session.Value(quicServiceContextKey{}) != "service" {
		t.Fatal("constructor services lost")
	}
	ctx, release, err := adapter.AcquireRuntimeOperation(session, nil)
	if err != nil {
		t.Fatal(err)
	}
	release()
	// The outer setup task is gone; a child still forks the physical session.
	_, childRelease, err := adapter.AcquireRuntimeOperation(session, nil)
	if err != nil {
		t.Fatal(err)
	}
	childRelease()
	if _, _, err := adapter.AcquireRuntimeOperation(ctx, nil); err == nil {
		t.Fatal("released setup task remained reusable")
	}
	cancel()
	if session.Err() != context.Canceled {
		t.Fatal("physical cancellation lost")
	}
}

func TestSessionContextRejectsMissingPhysicalAdmission(t *testing.T) {
	if _, err := quicServerSessionContext(context.Background(), context.Background()); err == nil {
		t.Fatal("missing lineage accepted")
	}
}
