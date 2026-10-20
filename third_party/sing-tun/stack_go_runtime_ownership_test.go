package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type goOwnershipHandler struct {
	Handler
	fixture *ownershipFixture
	entered chan FlowOwnership
	release chan struct{}
	finished chan struct{}
}
func (h *goOwnershipHandler) JudgeFlow(uint8,netip.AddrPort,netip.AddrPort,[]byte) FlowVerdict {
	return FlowVerdict{Action:ActionAccept,Ownership:h.fixture.flow()}
}
func (h *goOwnershipHandler) NewConnectionEx(ctx context.Context,conn net.Conn,_,_ M.Socksaddr,onClose N.CloseHandlerFunc) {
	owner,_:=ctx.Value(ownershipContextKey{}).(FlowOwnership)
	h.entered<-owner
	conn.Close()
	<-h.release
	if onClose!=nil{onClose(nil)}
	close(h.finished)
}
func (h *goOwnershipHandler) NewPacketConnectionEx(ctx context.Context,conn N.PacketConn,_,_ M.Socksaddr,onClose N.CloseHandlerFunc) {
	owner,_:=ctx.Value(ownershipContextKey{}).(FlowOwnership)
	h.entered<-owner
	conn.Close()
	<-h.release
	if onClose!=nil{onClose(nil)}
	close(h.finished)
}

func TestGoHandlerLaunchPinsAcceptedGraphWithNilTracker(t *testing.T) {
	for _,protocol:=range []uint8{uint8(header.TCPProtocolNumber),uint8(header.UDPProtocolNumber)} {
		f:=newOwnershipFixture();h:=&goOwnershipHandler{fixture:f,entered:make(chan FlowOwnership,1),release:make(chan struct{}),finished:make(chan struct{})}
		unblock:=sync.OnceFunc(func(){close(h.release)})
		device:=NewMemoryTun(MemoryTunOptions{MTU:1500})
		stack,err:=NewGo(StackOptions{Context:context.Background(),Tun:device,TunOptions:Options{MTU:1500},Handler:h,Logger:logger.NOP(),UDPTimeout:time.Minute})
		if err!=nil{device.Close();t.Fatal(err)}
		t.Cleanup(func(){unblock();stack.Close();device.Close()})
		if err=stack.Start();err!=nil{t.Fatal(err)}
		raw,_:=ownershipPacket(protocol);if _,err=device.Write(raw);err!=nil{t.Fatal(err)}
		var received FlowOwnership
		select{case received=<-h.entered:case <-time.After(5*time.Second):t.Fatal("handler admission watchdog")}
		if received==nil{t.Fatal("handler lost accepted graph context")}
		f.retire();stack.Close();assertStillOwned(t,f)
		continuation,err:=received.Retain();if err!=nil{t.Fatal("close-before-handler-return invalidated borrowed token")};continuation.Release()
		unblock();waitOwnership(t,h.finished);waitOwnership(t,f.closed)
	}
}

func TestPacketLaunchContinuationOutlivesStructuralSlot(t *testing.T) {
	// This is a helper-level close-before-launch oracle. Actual Go ingress is
	// exercised separately by TestGoHandlerLaunchPinsAcceptedGraphWithNilTracker.
	f:=newOwnershipFixture();root:=f.flow();slot:=flowOwnershipSlot{owner:root}
	packet:=FlowVerdict{Action:ActionAccept,Ownership:f.flow()}
	launch,err:=slot.retain();if err!=nil{t.Fatal(err)}
	packet.Release();f.retire();slot.release();assertStillOwned(t,f);releaseFlow(launch);waitOwnership(t,f.closed)
}

func TestGoDNSDispatchPreservesContextAndReleasesImmediateHandoff(t *testing.T) {
	f:=newOwnershipFixture();h:=&dnsOwnershipHandler{fixture:f}
	v:=FlowVerdict{Action:ActionHijackDNS,Ownership:f.flow()}
	deliverDNSPacket(h,context.Background(),&v,nil,M.Socksaddr{},M.Socksaddr{},nil)
	if h.retained==nil || v.Ownership!=nil{t.Fatal("DNS handoff failed")}
	f.retire();assertStillOwned(t,f);h.retained.Release();waitOwnership(t,f.closed)
}

type dnsOwnershipHandler struct { Handler; fixture *ownershipFixture; retained FlowOwnership }
func (h *dnsOwnershipHandler) NewDNSPacketEx(ctx context.Context,_ []byte,_,_ M.Socksaddr,_ N.PacketWriter) {
	owner,_:=ctx.Value(ownershipContextKey{}).(FlowOwnership)
	if owner!=nil{h.retained,_=owner.Retain()}
}
