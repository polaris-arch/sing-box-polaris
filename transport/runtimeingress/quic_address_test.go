//go:build with_quic

package runtimeingress

import (
	"net"
	"sync/atomic"
	"testing"
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
