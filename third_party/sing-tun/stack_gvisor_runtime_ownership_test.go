//go:build with_gvisor

package tun

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing/common/logger"
)

func TestGVisorICMPDuplicateInstallOwnsOneMapEntry(t *testing.T) {
	for _,v6:=range []bool{false,true} {
		f:=newOwnershipFixture();port:=&ownershipPort{fixture:f,address:netip.IPv4Unspecified()};f.port=port
		forwarder:=NewICMPForwarder(nil,&ownershipHandler{},logger.NOP());t.Cleanup(func(){forwarder.Close()})
		key:=icmpFlowKey{v6:v6,source:netip.MustParseAddr("198.18.0.2"),destination:netip.MustParseAddr("203.0.113.1"),identifier:7}
		start:=make(chan struct{});unblock:=sync.OnceFunc(func(){close(start)});t.Cleanup(unblock);finished:=make(chan struct{},2)
		for range 2 { go func(){
			defer func(){finished<-struct{}{}}()
			verdict:=FlowVerdict{Action:ActionFlow,Port:port,Ownership:f.flow()};defer verdict.Release()
			packet:=stack.NewPacketBuffer(stack.PacketBufferOptions{Payload:buffer.MakeWithData([]byte{1})});defer packet.DecRef()
			<-start
			forwarder.installFlow(key,verdict,packet)
		}() }
		unblock();waitOwnership(t,finished);waitOwnership(t,finished)
		forwarder.flowAccess.Lock();count:=len(forwarder.flows);forwarder.flowAccess.Unlock();if count!=1{t.Fatal("duplicate key overwrote or leaked map ownership")}
		use:=forwarder.lookupFlow(key);if use==nil{t.Fatal("lookup")}
		use.flow.close(FlowCloseFinished);f.retire();forwarder.Close();assertStillOwned(t,f);use.release();waitOwnership(t,f.closed)
	}
}

func TestGVisorLazyCloseBeforeHandshakeReleasesStructuralToken(t *testing.T) {
	f:=newOwnershipFixture();conn:=&gLazyConn{ownership:flowOwnershipSlot{owner:f.flow()}}
	launch,err:=conn.ownership.retain();if err!=nil{t.Fatal(err)}
	f.retire();conn.Close();assertStillOwned(t,f);releaseFlow(launch);waitOwnership(t,f.closed)
}

func TestGVisorUDPPreparedWriterCloseBeforePublication(t *testing.T) {
	f:=newOwnershipFixture();writer:=&UDPBackWriter{ownership:flowOwnershipSlot{owner:f.flow()}}
	launch,err:=writer.retainFlowOwnership();if err!=nil{t.Fatal(err)}
	f.retire();writer.Close();assertStillOwned(t,f);releaseFlow(launch);waitOwnership(t,f.closed)
}
