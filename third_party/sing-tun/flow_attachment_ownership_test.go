package tun

import (
	"errors"
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

func TestCopiedReturnCallbackSealedAndRunningCallbackJoined(t *testing.T) {
	for _,headroom:=range []bool{false,true} {
		f:=newOwnershipFixture(); entered,release:=make(chan struct{}),make(chan struct{}); unblock:=sync.OnceFunc(func(){close(release)});t.Cleanup(unblock)
		port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1")};f.port=port
		w:=&ownershipWriteback{headroom:func()int{close(entered);<-release;return 0}}
		d,_:=ownershipDispatcher(&ownershipHandler{},w);t.Cleanup(d.Close)
		root:=f.flow();use:=d.natFor(port,root);if use==nil{t.Fatal("attach")};r:=use.returnPath;copied:=port.copiedReturn()
		finished:=make(chan struct{});go func(){defer close(finished);if headroom{copied.ReturnHeadroom()}else{copied.ReturnPackets(nil)}}()
		waitOwnership(t,entered);f.retire();root.Release();use.release();assertStillOwned(t,f)
		// Seal is synchronous when the last structural use disappears. A copy
		// retained by the Port cannot start a second callback after this point.
		if copied.ReturnHeadroom()!=0 {t.Fatal("late callback entered sealed target")}
		unblock();waitOwnership(t,finished);waitOwnership(t,r.detached);waitOwnership(t,f.closed)
	}
}

func TestSharedPortNATAttachmentsDrainIndependently(t *testing.T) {
	f:=newOwnershipFixture();port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1")};f.port=port;root:=f.flow()
	d1,_:=ownershipDispatcher(&ownershipHandler{},&ownershipWriteback{});d2,_:=ownershipDispatcher(&ownershipHandler{},&ownershipWriteback{});t.Cleanup(d1.Close);t.Cleanup(d2.Close)
	u1,u2:=d1.natFor(port,root),d2.natFor(port,root);if u1.returnPath.nat!=u2.returnPath.nat{t.Fatal("global NAT not shared")}
	r1,r2:=u1.returnPath,u2.returnPath;d1.Close();u1.release();waitOwnership(t,r1.detached)
	portNATAccess.Lock();kept:=portNATs[port]==r2.nat;portNATAccess.Unlock();if !kept{t.Fatal("first detach removed second attachment")}
	f.retire();root.Release();u2.release();waitOwnership(t,r2.detached);waitOwnership(t,f.closed)
	portNATAccess.Lock();_,exists:=portNATs[port];portNATAccess.Unlock();if exists{t.Fatal("last detach retained global NAT")}
}

func TestStagedWritePinsPortAfterTableRemoval(t *testing.T) {
	f:=newOwnershipFixture();entered,release:=make(chan struct{}),make(chan struct{});unblock:=sync.OnceFunc(func(){close(release)});t.Cleanup(unblock)
	port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1"),write:func([][]byte)error{close(entered);<-release;return nil}};f.port=port
	d,s:=ownershipDispatcher(&ownershipHandler{judge:func()FlowVerdict{return FlowVerdict{Action:ActionFlow,Port:port,Ownership:f.flow()}}},&ownershipWriteback{});t.Cleanup(d.Close)
	raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber));key:=p.flowKey();if !s.DispatchParsed(raw,ForwardFrameMeta{},&p){t.Fatal("flow not installed")}
	finished:=make(chan struct{});go func(){defer close(finished);s.Flush()}();waitOwnership(t,entered)
	s.teardownFlow(key,FlowCloseReset);f.retire();d.Close();assertStillOwned(t,f)
	unblock();waitOwnership(t,finished);waitOwnership(t,f.closed)
	s.access.Lock();remaining:=len(s.ports);s.access.Unlock();if remaining!=0{t.Fatal("retired staging entry retained")}
}

func TestCloseBeforeFlushDiscardsQueuedOwnership(t *testing.T) {
	f:=newOwnershipFixture();port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1"),write:func([][]byte)error{t.Error("closed queue was written");return nil}};f.port=port
	d,s:=ownershipDispatcher(&ownershipHandler{judge:func()FlowVerdict{return FlowVerdict{Action:ActionFlow,Port:port,Ownership:f.flow()}}},&ownershipWriteback{});t.Cleanup(d.Close)
	raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber));s.DispatchParsed(raw,ForwardFrameMeta{},&p);f.retire();d.Close();s.Flush();waitOwnership(t,f.closed)
}

func TestFragmentAndLookupOutliveStructuralRemoval(t *testing.T) {
	f:=newOwnershipFixture();port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1")};f.port=port
	d,s:=ownershipDispatcher(&ownershipHandler{judge:func()FlowVerdict{return FlowVerdict{Action:ActionFlow,Port:port,Ownership:f.flow()}}},&ownershipWriteback{});t.Cleanup(d.Close)
	raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber));key:=p.flowKey();s.DispatchParsed(raw,ForwardFrameMeta{},&p);s.Flush()
	s.access.Lock();flow:=s.table[key].flow;s.access.Unlock()
	use:=flow.nat.lookupOwned(flow.reverseKey);if use==nil{t.Fatal("retained lookup")}
	r:=flow.attachment.returnPath;fragment:=fragmentKey{source:port.address,destination:p.source.Addr(),protocol:uint8(header.UDPProtocolNumber),id:7}
	r.fragments.insert(fragment,use,&flow.reverseRule,8,d.now());use.release()
	s.teardownFlow(key,FlowCloseReset);f.retire();assertStillOwned(t,f)
	entry:=r.fragments.lookup(fragment,fragmentInfo{offset:8,payload:make([]byte,8)},d.now());if entry==nil{t.Fatal("fragment lost after structural removal")}
	r.fragments.clear();assertStillOwned(t,f);entry.use.release();waitOwnership(t,f.closed)
}

func TestTrackerFinishDoesNotReleaseTombstone(t *testing.T) {
	f:=newOwnershipFixture();port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1")};f.port=port
	d,s:=ownershipDispatcher(&ownershipHandler{judge:func()FlowVerdict{return FlowVerdict{Action:ActionFlow,Port:port,Ownership:f.flow()}}},&ownershipWriteback{});t.Cleanup(d.Close)
	raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber));key:=p.flowKey();s.DispatchParsed(raw,ForwardFrameMeta{},&p);s.Flush()
	s.access.Lock();entry:=s.table[key];flow:=entry.flow;s.access.Unlock();flow.report(FlowCloseFinished)
	use:=flow.nat.lookupOwned(flow.reverseKey);if use==nil{t.Fatal("lookup after tracker report")}
	s.access.Lock();tombstoneEntry(entry,d.now());s.access.Unlock();f.retire();assertStillOwned(t,f)
	s.teardownFlow(key,FlowCloseReset);assertStillOwned(t,f);use.release();waitOwnership(t,f.closed)
}

func TestDetachFailureQuarantinesReservation(t *testing.T) {
	f:=newOwnershipFixture();attempted:=make(chan struct{});port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1"),detach:func(Return)error{close(attempted);return errors.New("native detach unconfirmed")}};f.port=port;root:=f.flow()
	d,_:=ownershipDispatcher(&ownershipHandler{},&ownershipWriteback{});t.Cleanup(d.Close);use:=d.natFor(port,root);r:=use.returnPath
	f.retire();root.Release();use.release();waitOwnership(t,attempted)
	// The error is deliberately sticky. It must not manufacture successful
	// resource drain, remove global storage, or retry an uncertain detach.
	assertStillOwned(t,f);d.portsAccess.Lock();kept:=d.ports[port]==r;d.portsAccess.Unlock();if !kept{t.Fatal("quarantine lost")}
}

func TestReentrantPortAttachCanCloseDispatcher(t *testing.T) {
	f:=newOwnershipFixture();port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1")};f.port=port;root:=f.flow()
	d,_:=ownershipDispatcher(&ownershipHandler{},&ownershipWriteback{});t.Cleanup(d.Close);port.attach=func(Return)error{d.Close();return nil}
	finished:=make(chan struct{});go func(){defer close(finished);if use:=d.natFor(port,root);use!=nil{use.release()}}();waitOwnership(t,finished)
	f.retire();root.Release();waitOwnership(t,f.closed)
}

func TestIdleRetiredAttachmentsDoNotRequireTUNClose(t *testing.T) {
	d,_:=ownershipDispatcher(&ownershipHandler{},&ownershipWriteback{});t.Cleanup(d.Close)
	for range 8 {
		f:=newOwnershipFixture();port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1")};f.port=port;root:=f.flow();use:=d.natFor(port,root)
		f.retire();root.Release();use.release();waitOwnership(t,use.returnPath.completion);waitOwnership(t,f.closed)
	}
	d.portsAccess.Lock();count:=len(d.ports);d.portsAccess.Unlock();if count!=0{t.Fatalf("idle obsolete attachments: %d",count)}
}

// This wrapper blocks only the attachment's final Release, after NAT cleanup.
// Its Retain method deliberately returns the underlying independent handle.
type attachmentTailOwner struct {
	PortOwnership
	entered chan struct{}
	release <-chan struct{}
}
func (o *attachmentTailOwner) Release() { close(o.entered); <-o.release; o.PortOwnership.Release() }
type attachmentTailFlow struct {
	FlowOwnership
	entered chan struct{}
	release <-chan struct{}
}
func (o *attachmentTailFlow) RetainPort(port Port) (PortOwnership, error) {
	owner, err := o.FlowOwnership.RetainPort(port)
	if err != nil { return nil, err }
	return &attachmentTailOwner{owner, o.entered, o.release}, nil
}

func TestWaitDetachedIncludesCleanupTail(t *testing.T) {
	f := newOwnershipFixture()
	port := &ownershipPort{fixture:f, address:netip.MustParseAddr("192.0.2.1")}; f.port = port
	d, _ := ownershipDispatcher(&ownershipHandler{}, &ownershipWriteback{})
	entered, release := make(chan struct{}), make(chan struct{})
	root := f.flow()
	use := d.natFor(port, &attachmentTailFlow{root, entered, release}); r := use.returnPath
	unblock := sync.OnceFunc(func(){ close(release) })
	t.Cleanup(func(){ unblock(); waitOwnership(t, r.completion) })
	f.retire(); root.Release(); d.Close(); use.release()
	waitOwnership(t, entered)
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if err := d.WaitDetached(ctx); !errors.Is(err, context.Canceled) { t.Fatalf("incomplete cleanup certified: %v", err) }
	d.portsAccess.Lock(); kept := d.ports[port] == r; d.portsAccess.Unlock()
	if !kept { t.Fatal("cleanup tail removed from completion census") }
	unblock(); waitOwnership(t, r.completion)
	if err := d.WaitDetached(context.Background()); err != nil { t.Fatal(err) }
	waitOwnership(t, f.closed)
}

func TestDetachPanicIsStickyQuarantine(t *testing.T) {
	f := newOwnershipFixture()
	port := &ownershipPort{fixture:f, address:netip.MustParseAddr("192.0.2.1"), detach:func(Return)error{ panic("native uncertain") }}; f.port = port
	d, _ := ownershipDispatcher(&ownershipHandler{}, &ownershipWriteback{})
	root := f.flow(); use := d.natFor(port, root); r := use.returnPath
	f.retire(); root.Release(); d.Close(); use.release()
	waitOwnership(t, r.completion); waitOwnership(t, r.fragmentDone)
	if err := d.WaitDetached(context.Background()); err == nil { t.Fatal("panic certified as detach") }
	if err := d.WaitDetached(context.Background()); err == nil { t.Fatal("quarantine result was not sticky") }
	assertStillOwned(t, f)
	d.portsAccess.Lock(); kept := d.ports[port] == r; d.portsAccess.Unlock()
	if !kept { t.Fatal("quarantine evidence removed") }
}

func TestAttachPanicAfterCopiedCallbackQuarantines(t *testing.T) {
	f := newOwnershipFixture()
	port := &ownershipPort{fixture:f, address:netip.MustParseAddr("192.0.2.1"), attach:func(Return)error{ panic("after native copy") }}; f.port = port
	d, _ := ownershipDispatcher(&ownershipHandler{}, &ownershipWriteback{})
	root := f.flow()
	if use := d.natFor(port, root); use != nil { t.Fatal("uncertain attachment admitted") }
	d.portsAccess.Lock(); r := d.ports[port]; d.portsAccess.Unlock()
	if r == nil { t.Fatal("lost uncertain reservation") }
	waitOwnership(t, r.ready); waitOwnership(t, r.completion)
	if got := port.copiedReturn().ReturnHeadroom(); got != 0 { t.Fatal("copied callback entered after panic") }
	f.retire(); root.Release(); d.Close()
	if err := d.WaitDetached(context.Background()); !errors.Is(err, errAttachmentPanic) { t.Fatalf("uncertain attachment certified: %v", err) }
	assertStillOwned(t, f)
}

type panickingPortAcquisition struct { FlowOwnership }
func (p *panickingPortAcquisition) RetainPort(Port) (PortOwnership, error) { panic("acquisition uncertain") }

func TestRetainPortPanicPublishesStickyReadiness(t *testing.T) {
	f := newOwnershipFixture()
	port := &ownershipPort{fixture:f, address:netip.MustParseAddr("192.0.2.1")}; f.port = port
	d, _ := ownershipDispatcher(&ownershipHandler{}, &ownershipWriteback{})
	root := f.flow(); defer root.Release()
	if use := d.natFor(port, &panickingPortAcquisition{root}); use != nil { t.Fatal("uncertain acquisition admitted") }
	d.portsAccess.Lock(); r := d.ports[port]; d.portsAccess.Unlock()
	if r == nil { t.Fatal("lost uncertain acquisition evidence") }
	waitOwnership(t, r.ready); waitOwnership(t, r.completion)
	d.Close()
	if err := d.WaitDetached(context.Background()); !errors.Is(err, errAttachmentPanic) { t.Fatalf("uncertain acquisition certified: %v", err) }
	if err := d.WaitDetached(context.Background()); !errors.Is(err, errAttachmentPanic) { t.Fatalf("lost sticky uncertainty: %v", err) }
}
