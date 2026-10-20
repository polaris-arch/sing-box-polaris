package tun

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
)

// These vendor fixtures exercise the actual dispatcher/storage code through the
// adapter contract. Cross-graph owner correctness is tested in runtimegraph;
// this deliberately has no production reference-count implementation.
type ownershipFixture struct {
	access sync.Mutex
	refs int
	retired bool
	retiring chan struct{}
	closed chan struct{}
	port Port
}
type flowFixtureHandle struct { fixture *ownershipFixture; released bool }
type portFixtureHandle struct { fixture *ownershipFixture; released bool }
type ownershipContextKey struct{}

func newOwnershipFixture() *ownershipFixture {
	return &ownershipFixture{retiring: make(chan struct{}), closed: make(chan struct{})}
}
func (f *ownershipFixture) flow() FlowOwnership {
	f.access.Lock(); defer f.access.Unlock()
	f.refs++
	return &flowFixtureHandle{fixture: f}
}
func (f *ownershipFixture) count() int { f.access.Lock(); defer f.access.Unlock(); return f.refs }
func (f *ownershipFixture) retire() {
	f.access.Lock(); defer f.access.Unlock()
	if !f.retired { f.retired = true; close(f.retiring); if f.refs == 0 { close(f.closed) } }
}
func (h *flowFixtureHandle) Retain() (FlowOwnership, error) {
	f := h.fixture; f.access.Lock(); defer f.access.Unlock()
	if h.released || f.refs == 0 { return nil, errFlowOwnershipClosed }
	f.refs++; return &flowFixtureHandle{fixture:f}, nil
}
func (h *flowFixtureHandle) BindContext(ctx context.Context) context.Context { return context.WithValue(ctx, ownershipContextKey{}, h) }
func (h *flowFixtureHandle) RetainPort(port Port) (PortOwnership, error) {
	f := h.fixture; f.access.Lock(); defer f.access.Unlock()
	if h.released || f.refs == 0 || port != f.port { return nil, errFlowOwnershipClosed }
	f.refs++; return &portFixtureHandle{fixture:f}, nil
}
func (h *flowFixtureHandle) Release() {
	f:=h.fixture; f.access.Lock(); defer f.access.Unlock()
	if h.released { return }; h.released=true; f.refs--
	if f.refs == 0 && f.retired { close(f.closed) }
}
func (h *portFixtureHandle) Retain() (PortOwnership, error) {
	f:=h.fixture; f.access.Lock(); defer f.access.Unlock()
	if h.released || f.refs == 0 { return nil, errFlowOwnershipClosed }
	f.refs++; return &portFixtureHandle{fixture:f}, nil
}
func (h *portFixtureHandle) Retiring() <-chan struct{} { return h.fixture.retiring }
func (h *portFixtureHandle) Release() {
	f:=h.fixture; f.access.Lock(); defer f.access.Unlock()
	if h.released { return }; h.released=true; f.refs--
	if f.refs == 0 && f.retired { close(f.closed) }
}

type ownershipHandler struct { Handler; judge func() FlowVerdict }
func (h *ownershipHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict { return h.judge() }
type ownershipWriteback struct { headroom func() int; write func([][]byte) error }
func (w *ownershipWriteback) ReturnHeadroom() int { if w.headroom != nil { return w.headroom() }; return 0 }
func (w *ownershipWriteback) WriteReturnPackets(p [][]byte) error { if w.write != nil { return w.write(p) }; return nil }

type ownershipPort struct {
	fixture *ownershipFixture
	access sync.Mutex
	returns []Return
	address netip.Addr
	mtu uint32
	attach func(Return) error
	detach func(Return) error
	write func([][]byte) error
}
func (p *ownershipPort) live() { if p.fixture != nil && p.fixture.count() <= 0 { panic("Port used after ownership release") } }
func (p *ownershipPort) PortAddresses() (netip.Addr, netip.Addr) { p.live(); return p.address, netip.IPv6Unspecified() }
func (p *ownershipPort) PortMTU() uint32 { p.live(); return p.mtu }
func (p *ownershipPort) AttachReturn(r Return) error {
	p.live(); p.access.Lock(); p.returns=append(p.returns,r); p.access.Unlock()
	if p.attach != nil { return p.attach(r) }; return nil
}
func (p *ownershipPort) DetachReturn(r Return) error { p.live(); if p.detach != nil { return p.detach(r) }; return nil }
func (p *ownershipPort) WritePackets(packets [][]byte) error { p.live(); if p.write != nil { return p.write(packets) }; return nil }
func (p *ownershipPort) copiedReturn() Return { p.access.Lock(); defer p.access.Unlock(); return p.returns[len(p.returns)-1] }

func ownershipPacket(protocol uint8) ([]byte, forwardPacket) {
	source := netip.MustParseAddrPort("198.18.0.2:12345")
	destination := netip.MustParseAddrPort("203.0.113.1:443")
	if protocol == uint8(header.UDPProtocolNumber) {
		raw := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+1)
		goEncodeUDPPacket(raw,4,source,destination,[]byte{1},1)
		parsed,_:=parseForwardPacket(raw); return raw,parsed
	}
	raw:=make([]byte,header.IPv4MinimumSize+header.TCPMinimumSize)
	ip:=header.IPv4(raw); ip.Encode(&header.IPv4Fields{TotalLength:uint16(len(raw)),TTL:64,Protocol:protocol,SrcAddr:source.Addr(),DstAddr:destination.Addr()})
	tcp:=header.TCP(ip.Payload()); tcp.Encode(&header.TCPFields{SrcPort:source.Port(),DstPort:destination.Port(),DataOffset:header.TCPMinimumSize,Flags:header.TCPFlagSyn})
	parsed,_:=parseForwardPacket(raw); return raw,parsed
}
func waitOwnership(t *testing.T, done <-chan struct{}) {
	t.Helper(); select { case <-done: case <-time.After(5*time.Second): t.Fatal("ownership completion watchdog") }
}
func assertStillOwned(t *testing.T, f *ownershipFixture) {
	t.Helper(); select { case <-f.closed: t.Fatal("owner closed before actual completion"); default: }
}
func ownershipDispatcher(h Handler, w *ownershipWriteback) (*ForwardDispatcher,*ForwardStage) {
	d:=NewForwardDispatcher(h,w,logger.NOP(),UDPNatOptions{},time.Minute); return d,d.NewStage(nil)
}

func TestFlowVerdictOwnershipTransferAndClone(t *testing.T) {
	f:=newOwnershipFixture()
	v:=FlowVerdict{Action:ActionAccept,Ownership:f.flow()}
	copyOnly:=v
	if f.count()!=1 { t.Fatal("value copy retained") }
	clone,err:=v.CloneForDelivery(); if err!=nil { t.Fatal(err) }
	moved:=v.Take(); if v.Ownership!=nil { t.Fatal("move retained source") }
	moved.Release(); copyOnly.Release()
	if f.count()!=1 { t.Fatal("clone not independent") }
	f.retire(); assertStillOwned(t,f); clone.Release(); waitOwnership(t,f.closed)
	legacy:=FlowVerdict{Action:ActionAccept}; clone,err=legacy.CloneForDelivery(); if err!=nil { t.Fatal(err) }; clone.Release()
}

func TestFlowVerdictClassificationDisposesResources(t *testing.T) {
	for _,action:=range []FlowAction{ActionAccept,ActionFlow,ActionReject,ActionDrop,ActionBypass,ActionHijackDNS} {
		f:=newOwnershipFixture(); v:=FlowVerdict{Action:action,Ownership:f.flow(),NewTracker:func() FlowTracker { t.Fatal("classification constructed tracker"); return nil }}
		if v.ClassifyAndRelease()!=action || v.Ownership!=nil || v.Port!=nil || v.NewTracker!=nil { t.Fatal("classification leaked object") }
		f.retire(); waitOwnership(t,f.closed)
	}
}

func TestAcceptCacheDeliverySurvivesRemoval(t *testing.T) {
	for _,protocol:=range []uint8{uint8(header.TCPProtocolNumber),uint8(header.UDPProtocolNumber)} {
		f:=newOwnershipFixture()
		d,s:=ownershipDispatcher(&ownershipHandler{judge:func() FlowVerdict{return FlowVerdict{Action:ActionAccept,Ownership:f.flow()}}},&ownershipWriteback{})
		t.Cleanup(d.Close)
		raw,p:=ownershipPacket(protocol)
		if s.DispatchParsed(raw,ForwardFrameMeta{},&p) { t.Fatal("accept consumed") }; p.verdict.Release()
		raw,p=ownershipPacket(protocol)
		if s.DispatchParsed(raw,ForwardFrameMeta{},&p) { t.Fatal("cache hit consumed") }
		f.retire(); d.Close(); assertStillOwned(t,f)
		if p.verdict.Ownership==nil { t.Fatal("cache hit lost admission") }
		p.verdict.Release(); waitOwnership(t,f.closed)
	}
}

func TestJudgeCloseBeforeStagePublication(t *testing.T) {
	f:=newOwnershipFixture(); entered,release:=make(chan struct{}),make(chan struct{})
	unblock:=sync.OnceFunc(func(){close(release)}); t.Cleanup(unblock)
	d,s:=ownershipDispatcher(&ownershipHandler{judge:func() FlowVerdict { v:=FlowVerdict{Action:ActionAccept,Ownership:f.flow()}; close(entered); <-release; return v }},&ownershipWriteback{})
	t.Cleanup(d.Close); finished:=make(chan struct{})
	go func(){defer close(finished); raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber)); s.DispatchParsed(raw,ForwardFrameMeta{},&p); p.verdict.Release()}()
	waitOwnership(t,entered); f.retire(); d.Close(); assertStillOwned(t,f); unblock(); waitOwnership(t,finished); waitOwnership(t,f.closed)
}

func TestDuplicateJudgeLosingVerdictReleased(t *testing.T) {
	f:=newOwnershipFixture(); entered:=make(chan struct{},2); release:=make(chan struct{}); unblock:=sync.OnceFunc(func(){close(release)}); t.Cleanup(unblock)
	d,s:=ownershipDispatcher(&ownershipHandler{judge:func() FlowVerdict { v:=FlowVerdict{Action:ActionAccept,Ownership:f.flow()}; entered<-struct{}{}; <-release; return v }},&ownershipWriteback{})
	t.Cleanup(d.Close); finished:=make(chan struct{},2)
	for range 2 { go func(){raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber)); s.DispatchParsed(raw,ForwardFrameMeta{},&p); p.verdict.Release(); finished<-struct{}{}}() }
	waitOwnership(t,entered); waitOwnership(t,entered); unblock(); waitOwnership(t,finished); waitOwnership(t,finished)
	if f.count()!=1 { t.Fatalf("expected only winning cache handle, got %d",f.count()) }
	f.retire(); d.Close(); waitOwnership(t,f.closed)
}

func TestCreateFlowFallbackRetainsCaller(t *testing.T) {
	for _,variant:=range []string{"invalid-address","ipv6-mtu","family","attach-failure","nil-port"} {
		t.Run(variant,func(t *testing.T){
			f:=newOwnershipFixture(); port:=&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1")}; f.port=port
			v:=FlowVerdict{Action:ActionFlow,Port:port,Ownership:f.flow()}; raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber)); _=raw
			switch variant { case "invalid-address": port.address=netip.Addr{}; case "ipv6-mtu":p.ipVersion=6;port.mtu=1279; case "family":v.Destination=netip.MustParseAddrPort("[2001:db8::1]:53"); case "attach-failure":port.attach=func(Return)error{return errors.New("attach")};case "nil-port":v.Port=nil }
			d,s:=ownershipDispatcher(&ownershipHandler{judge:func()FlowVerdict{return v.Take()}},&ownershipWriteback{});t.Cleanup(d.Close)
			if variant!="nil-port" { flow,result:=s.createFlow(&p,v);if flow!=nil || result!=createFlowUnsupported {t.Fatal("expected fallback")}; if v.Ownership==nil {t.Fatal("caller token consumed by failed creation")} }
			v.Release();f.retire();d.Close();waitOwnership(t,f.closed)
		})
	}
}

func TestDecisionOnlyCacheHasNoGraphRetention(t *testing.T) {
	for _,action:=range []FlowAction{ActionDrop,ActionReject} {
		f:=newOwnershipFixture(); d,s:=ownershipDispatcher(&ownershipHandler{judge:func()FlowVerdict{return FlowVerdict{Action:action,Ownership:f.flow()}}},&ownershipWriteback{});t.Cleanup(d.Close)
		raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber));s.DispatchParsed(raw,ForwardFrameMeta{},&p);p.verdict.Release();f.retire();waitOwnership(t,f.closed)
	}
}

func TestAcceptCacheAllStructuralReleaseEvents(t *testing.T) {
	for _,event:=range []string{"expiry","eviction","replacement","reset","close"} {
		t.Run(event,func(t *testing.T){
			f:=newOwnershipFixture();d,s:=ownershipDispatcher(&ownershipHandler{judge:func()FlowVerdict{return FlowVerdict{Action:ActionAccept,Ownership:f.flow()}}},&ownershipWriteback{});t.Cleanup(d.Close)
			raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber));key:=p.flowKey();s.DispatchParsed(raw,ForwardFrameMeta{},&p);p.verdict.Release()
			f.retire()
			switch event {
			case "expiry":s.access.Lock();s.sweep(int64(defaultUDPTimeout)+d.now()+1);s.access.Unlock();s.drainRetired()
			case "eviction":s.access.Lock();s.evictEntries(d.now());s.access.Unlock();s.drainRetired()
			case "replacement":s.access.Lock();s.insertEntry(key,&flowEntry{action:ActionDrop},d.now());s.access.Unlock();s.drainRetired()
			case "reset":d.ResetNetwork();s.Flush()
			case "close":d.Close()
			}
			waitOwnership(t,f.closed)
		})
	}
}

type exhaustedOwnershipPort struct { *ownershipPort }
func (*exhaustedOwnershipPort) PortSelectorRanges(uint8) []SelectorRange { return []SelectorRange{{Start:49152,Count:1}} }
func (*exhaustedOwnershipPort) ExpandSelectorRanges(uint8) bool { return false }
func (*exhaustedOwnershipPort) ReserveSelector(uint8,netip.AddrPort) bool { return false }
func (*exhaustedOwnershipPort) ReleaseSelector(uint8,netip.AddrPort) {}

func TestSelectorExhaustionReleasesCandidateBeforeScalarReject(t *testing.T) {
	f:=newOwnershipFixture();port:=&exhaustedOwnershipPort{&ownershipPort{fixture:f,address:netip.MustParseAddr("192.0.2.1")}};f.port=port
	d,s:=ownershipDispatcher(&ownershipHandler{judge:func()FlowVerdict{return FlowVerdict{Action:ActionFlow,Port:port,Ownership:f.flow()}}},&ownershipWriteback{});t.Cleanup(d.Close)
	raw,p:=ownershipPacket(uint8(header.UDPProtocolNumber));key:=p.flowKey();if !s.DispatchParsed(raw,ForwardFrameMeta{},&p){t.Fatal("exhaustion must reject")}
	s.access.Lock();entry:=s.table[key];scalar:=entry!=nil&&entry.action==ActionReject&&entry.flow==nil&&entry.verdict.Ownership==nil;s.access.Unlock();if !scalar{t.Fatal("exhaustion retained candidate in cache")}
	f.retire();waitOwnership(t,f.closed)
}
