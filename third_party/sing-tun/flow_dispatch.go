package tun

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	tcpEstablishedTimeout = 2*time.Hour + 4*time.Minute
	tcpTransitoryTimeout  = 4 * time.Minute
	tcpClosingTimeout     = 10 * time.Second

	defaultUDPTimeout = 5 * time.Minute

	defaultICMPTimeout = time.Minute

	flowTombstoneTimeout = 4 * time.Minute

	flowTableCapacity = 16384
	flowStageCapacity = 1024

	flowSweepInterval = 30 * time.Second
	flowSweepLimit    = flowTableCapacity / int(flowTombstoneTimeout/flowSweepInterval)
)

type ForwardWriteback interface {
	ReturnHeadroom() int
	WriteReturnPackets(packets [][]byte) error
}

type ForwardFrameMeta struct {
	needsChecksum  bool
	checksumStart  uint16
	checksumOffset uint16
	gsoType        uint8
	gsoSize        uint16
}

func (m *ForwardFrameMeta) completeChecksum(raw []byte) {
	if !m.needsChecksum {
		return
	}
	m.needsChecksum = false
	checksumAt := int(m.checksumStart) + int(m.checksumOffset)
	if int(m.checksumStart) >= len(raw) || checksumAt+2 > len(raw) {
		return
	}
	initial := binary.BigEndian.Uint16(raw[checksumAt:])
	raw[checksumAt], raw[checksumAt+1] = 0, 0
	transportChecksum := ^checksum.Checksum(raw[m.checksumStart:], initial)
	if transportChecksum == 0 {
		transportChecksum = 0xffff
	}
	binary.BigEndian.PutUint16(raw[checksumAt:], transportChecksum)
}

type flowEntry struct {
	action   FlowAction
	deadline int64
	idle     time.Duration
	flow     *forwardFlow
	verdict  FlowVerdict
}

type forwardFlow struct {
	ownership FlowOwnership
	attachment *attachmentUse
	nat          *portNAT
	mapping      *natMapping
	selectorKey  natSelectorKey
	owner        *ForwardStage
	reverseKey   flowKey
	forwardRule  rewriteRule
	reverseRule  rewriteRule
	effectiveMTU uint32
	protocol     uint8
	udpTimeout   time.Duration
	tracker      FlowTracker

	clientAddress            netip.Addr
	clientSelector           uint16
	clientDestinationAddress netip.Addr
	clientDestinationPort    uint16
	serverAddress            netip.Addr
	dnatAddress              bool
	dnatPort                 bool

	finForward  atomic.Bool
	established atomic.Bool
	finReverse  atomic.Bool
	reported    atomic.Bool
	closed      atomic.Bool
	lastReverse atomic.Int64
}

func (f *forwardFlow) report(reason FlowCloseReason) {
	if !f.reported.CompareAndSwap(false, true) {
		return
	}
	if f.tracker != nil {
		f.tracker.CloseFlow(reason)
	}
}

func (f *forwardFlow) close(reason FlowCloseReason) {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	f.report(reason)
}

func (f *forwardFlow) CloseFlow() {
	f.close(FlowCloseReset)
}

func (f *forwardFlow) observeReverse(packet *forwardPacket, now int64) {
	f.lastReverse.Store(now)
	if packet.protocol != uint8(header.TCPProtocolNumber) {
		return
	}
	if f.established.CompareAndSwap(false, true) && f.tracker != nil {
		f.tracker.FlowEstablished()
	}
	if packet.tcpFlags&header.TCPFlagRst != 0 {
		f.close(FlowCloseReset)
		return
	}
	if packet.tcpFlags&header.TCPFlagFin != 0 {
		f.finReverse.Store(true)
	} else if f.finReverse.Load() && f.finForward.Load() {
		f.report(FlowCloseFinished)
	}
}

type ForwardDispatcher struct {
	epoch        time.Time
	handler      Handler
	writeback    ForwardWriteback
	logger       logger.Logger
	udpTimeout   time.Duration
	udpMapping   NATMapping
	udpFiltering NATFiltering
	icmpTimeout  time.Duration

	closed          atomic.Bool
	portsAccess     sync.Mutex
	ports           map[Port]*portReturn
	returnTarget Return
	stagesAccess    sync.Mutex
	stages          []*ForwardStage
	stageCount      atomic.Int32
	resetGeneration atomic.Uint32
}

type stagedPort struct {
	attachment *attachmentUse
	packets [][]byte
}

type ForwardStage struct {
	dispatcher *ForwardDispatcher
	writeback  ForwardWriteback
	access     sync.Mutex
	table      map[flowKey]*flowEntry
	lastSweep  int64
	resetSeen  uint32
	retired []retiredFlowEntry

	exhaustedLogAt int64
	ports          []stagedPort
	writebackBatch [][]byte
}

func addrToTCPIP(addr netip.Addr) tcpip.Address {
	if addr.Is4() {
		return tcpip.AddrFrom4(addr.As4())
	}
	return tcpip.AddrFrom16(addr.As16())
}

func NewForwardDispatcher(handler Handler, writeback ForwardWriteback, logger logger.Logger, udpOptions UDPNatOptions, icmpTimeout time.Duration) *ForwardDispatcher {
	dispatcher := &ForwardDispatcher{
		epoch:        time.Now(),
		handler:      handler,
		writeback:    writeback,
		logger:       logger,
		udpTimeout:   udpOptions.Timeout,
		udpMapping:   udpOptions.Mapping,
		udpFiltering: udpOptions.Filtering,
		icmpTimeout:  icmpTimeout,
		ports:        make(map[Port]*portReturn),
	}
	if dispatcher.udpTimeout <= 0 {
		dispatcher.udpTimeout = defaultUDPTimeout
	}
	if dispatcher.icmpTimeout <= 0 {
		dispatcher.icmpTimeout = defaultICMPTimeout
	}
	return dispatcher
}

func (d *ForwardDispatcher) NewStage(writeback ForwardWriteback) *ForwardStage {
	if d == nil {
		return nil
	}
	if writeback == nil {
		writeback = d.writeback
	}
	stage := &ForwardStage{
		dispatcher: d,
		writeback:  writeback,
		table:      make(map[flowKey]*flowEntry),
		resetSeen:  d.resetGeneration.Load(),
	}
	d.stagesAccess.Lock()
	d.stages = append(d.stages, stage)
	d.stageCount.Store(int32(len(d.stages)))
	d.stagesAccess.Unlock()
	return stage
}

func (d *ForwardDispatcher) now() int64 {
	return int64(time.Since(d.epoch))
}

func (d *ForwardDispatcher) Close() {
	if d == nil || !d.closed.CompareAndSwap(false, true) { return }
	d.stagesAccess.Lock()
	stages := slices.Clone(d.stages)
	d.stagesAccess.Unlock()
	for _, stage := range stages {
		stage.access.Lock()
		for key, entry := range stage.table { stage.removeEntry(key, entry, FlowCloseReset) }
		queued := stage.ports
		stage.ports = nil
		stage.writebackBatch = nil
		stage.access.Unlock()
		for _, port := range queued { port.attachment.release() }
		stage.drainRetired()
	}
	d.portsAccess.Lock()
	paths := make([]*portReturn, 0, len(d.ports))
	for _, path := range d.ports { paths = append(paths, path); path.gate.seal() }
	d.portsAccess.Unlock()
	for _, path := range paths {
		path.fragments.clear()
		d.detachIdle(path)
	}
}

func (s *ForwardStage) Dispatch(packet []byte) bool {
	if s == nil || s.dispatcher.closed.Load() {
		return false
	}
	parsed, ok := parseForwardPacket(packet)
	if !ok {
		return false
	}
	defer parsed.verdict.Release()
	return s.dispatch(packet, &parsed, nil)
}

func (s *ForwardStage) DispatchParsed(packet []byte, meta ForwardFrameMeta, parsed *forwardPacket) bool {
	if s == nil || s.dispatcher.closed.Load() {
		return false
	}
	return s.dispatch(packet, parsed, &meta)
}

func (s *ForwardStage) dispatch(packet []byte, parsed *forwardPacket, meta *ForwardFrameMeta) bool {
	if parsed.fragment || !parsed.hasFlow { return false }
	key := parsed.flowKey()
	if handled, found := s.handleCached(key, parsed, packet, s.dispatcher.now(), meta); found { return handled }
	if parsed.protocol == uint8(header.TCPProtocolNumber) &&
		(parsed.tcpFlags&header.TCPFlagSyn == 0 || parsed.tcpFlags&header.TCPFlagAck != 0) { return false }
	return s.judgeAndInstall(key, parsed, packet, meta)
}

func (s *ForwardStage) teardownFlow(key flowKey, reason FlowCloseReason) {
	if s == nil || s.dispatcher.closed.Load() {
		return
	}
	s.access.Lock()
	entry, loaded := s.table[key]
	if loaded {
		s.removeEntry(key, entry, reason)
	}
	s.access.Unlock()
	s.drainRetired()
}

func (s *ForwardStage) handleCached(key flowKey, packet *forwardPacket, raw []byte, now int64, meta *ForwardFrameMeta) (bool, bool) {
	s.access.Lock()
	entry := s.table[key]
	if entry == nil { s.access.Unlock(); return false, false }
	if entryExpired(entry, now) {
		s.removeEntry(key, entry, FlowCloseTimeout)
		s.access.Unlock()
		s.drainRetired()
		return false, false
	}
	action := entry.action
	var flow *forwardFlow
	var owned *forwardUse
	var err error
	if action == ActionFlow {
		flow = entry.flow
		owned, err = retainForward(flow)
	} else if action == ActionAccept {
		packet.verdict.Release()
		packet.verdict, err = entry.verdict.CloneForDelivery()
	}
	if err != nil { s.access.Unlock(); return true, true }
	if action == ActionFlow && flow.closed.Load() {
		tombstoneEntry(entry, now)
		s.access.Unlock()
		owned.release()
		return true, true
	}
	if action == ActionAccept && packet.protocol == uint8(header.TCPProtocolNumber) {
		if packet.tcpFlags&header.TCPFlagRst != 0 { s.removeEntry(key, entry, FlowCloseReset) }
		if packet.tcpFlags&header.TCPFlagSyn == 0 { entry.idle = tcpEstablishedTimeout }
	}
	if action == ActionFlow { entry.idle = s.dispatcher.flowIdle(flow) }
	entry.deadline = now + int64(entry.idle)
	s.access.Unlock()
	defer s.drainRetired()
	defer owned.release()
	switch action {
	case ActionFlow:
		s.forwardToPort(flow, packet, raw, meta)
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if packet.tcpFlags&header.TCPFlagRst != 0 { flow.close(FlowCloseReset) }
			if packet.tcpFlags&header.TCPFlagFin != 0 { flow.finForward.Store(true) } else if flow.finForward.Load() && flow.finReverse.Load() { flow.report(FlowCloseFinished) }
		}
		return true, true
	case ActionAccept: return false, true
	case ActionReject: s.stageReject(packet, raw, meta); return true, true
	default: return true, true
	}
}

func (s *ForwardStage) judgeAndInstall(key flowKey, packet *forwardPacket, raw []byte, meta *ForwardFrameMeta) bool {
	d := s.dispatcher
	var firstPacket []byte
	if packet.protocol == uint8(header.UDPProtocolNumber) { firstPacket = header.UDP(packet.transport).Payload() }
	verdict := d.handler.JudgeFlow(packet.protocol, packet.source, packet.destination, firstPacket)
	defer verdict.Release()
	if verdict.Action == ActionBypass && verdict.Port != nil { verdict.Action = ActionFlow }
	if d.closed.Load() { return true }
	if handled, found := s.handleCached(key, packet, raw, d.now(), meta); found { return handled }
	var flow *forwardFlow
	var result createFlowResult
	if verdict.Action == ActionFlow && verdict.Port != nil {
		flow, result = s.createFlow(packet, verdict)
	}
	// Port calls and tracker construction above run without the table lock.
	// The winner is rechecked before publishing; a loser rolls back everything.
	s.access.Lock()
	now := d.now()
	if existing := s.table[key]; existing != nil && entryExpired(existing, now) { s.removeEntry(key, existing, FlowCloseTimeout) }
	if d.closed.Load() || s.table[key] != nil {
		s.access.Unlock()
		if flow != nil { s.releaseFlow(flow, FlowCloseReset) }
		s.drainRetired()
		if d.closed.Load() { return true }
		handled, _ := s.handleCached(key, packet, raw, now, meta)
		return handled
	}
	if flow != nil {
		entry := &flowEntry{action: ActionFlow, flow: flow, idle: d.flowIdle(flow)}
		entry.deadline = now + int64(entry.idle)
		s.insertEntry(key, entry, now)
		owned, err := retainForward(flow)
		s.access.Unlock()
		s.drainRetired()
		if err == nil { s.forwardToPort(flow, packet, raw, meta); owned.release() }
		return true
	}
	action := verdict.Action
	if action == ActionFlow && result == createFlowExhausted { action = ActionReject }
	switch action {
	case ActionReject, ActionDrop:
		s.installSimple(key, action, packet.protocol, now)
	case ActionHijackDNS:
		if packet.protocol == uint8(header.UDPProtocolNumber) { packet.verdict = verdict.Take() } else { s.installAccept(key, packet, &verdict, now) }
	default: s.installAccept(key, packet, &verdict, now)
	}
	s.access.Unlock()
	s.drainRetired()
	if action == ActionReject { s.stageReject(packet, raw, meta); return true }
	if action == ActionDrop { return true }
	if action == ActionHijackDNS && packet.protocol == uint8(header.UDPProtocolNumber) { d.hijackDNSPacket(packet); return true }
	return false
}

func (s *ForwardStage) installSimple(key flowKey, action FlowAction, protocol uint8, now int64) *flowEntry {
	entry := &flowEntry{action: action, idle: s.dispatcher.idleTimeout(protocol, false)}
	entry.deadline = now + int64(entry.idle)
	s.insertEntry(key, entry, now)
	return entry
}

func (s *ForwardStage) installAccept(key flowKey, packet *forwardPacket, verdict *FlowVerdict, now int64) {
	entry := s.installSimple(key, ActionAccept, packet.protocol, now)
	entry.verdict = verdict.Take()
	var err error
	packet.verdict, err = entry.verdict.CloneForDelivery()
	if err != nil { packet.verdict.Action = ActionDrop }
}

func (d *ForwardDispatcher) idleTimeout(protocol uint8, established bool) time.Duration {
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		if established {
			return tcpEstablishedTimeout
		}
		return tcpTransitoryTimeout
	case uint8(header.UDPProtocolNumber):
		return d.udpTimeout
	default:
		return d.icmpTimeout
	}
}

func (d *ForwardDispatcher) flowIdle(flow *forwardFlow) time.Duration {
	if flow.protocol == uint8(header.TCPProtocolNumber) && flow.finForward.Load() && flow.finReverse.Load() {
		return tcpClosingTimeout
	}
	if flow.udpTimeout > 0 {
		return flow.udpTimeout
	}
	established := flow.established.Load() && !flow.finForward.Load() && !flow.finReverse.Load()
	return d.idleTimeout(flow.protocol, established)
}

type createFlowResult uint8

const (
	createFlowOK createFlowResult = iota
	createFlowUnsupported
	createFlowExhausted
)

const exhaustedLogInterval = 5 * time.Second

func (s *ForwardStage) createFlow(packet *forwardPacket, verdict FlowVerdict) (*forwardFlow, createFlowResult) {
	owned, err := verdict.CloneForDelivery()
	if err != nil { return nil, createFlowUnsupported }
	defer owned.Release()
	var portAddress netip.Addr
	inet4Address, inet6Address := verdict.Port.PortAddresses()
	if packet.ipVersion == 6 {
		portAddress = inet6Address
	} else {
		portAddress = inet4Address
	}
	if !portAddress.IsValid() {
		return nil, createFlowUnsupported
	}
	effectiveMTU := verdict.Port.PortMTU()
	if packet.ipVersion == 6 && effectiveMTU != 0 && effectiveMTU < header.IPv6MinimumMTU {
		return nil, createFlowUnsupported
	}
	isICMP := isICMPProtocol(packet.protocol)
	clientDestinationAddress := packet.destination.Addr()
	clientDestinationPort := packet.destination.Port()
	serverAddress := clientDestinationAddress
	serverPort := clientDestinationPort
	if verdict.Destination.Addr().IsValid() {
		serverAddress = verdict.Destination.Addr()
		if serverAddress.Is4() != clientDestinationAddress.Is4() {
			return nil, createFlowUnsupported
		}
	}
	if verdict.Destination.Port() != 0 && !isICMP {
		serverPort = verdict.Destination.Port()
	}
	attachment := s.dispatcher.natFor(verdict.Port, owned.Ownership)
	if attachment == nil { return nil, createFlowUnsupported }
	keepAttachment := false
	defer func() { if !keepAttachment { attachment.release() } }()
	nat := attachment.returnPath.nat
	server := netip.AddrPortFrom(serverAddress, serverPort)
	reservation, reserved := nat.reserveForPort(s.dispatcher, verdict.Port, packet.protocol, portAddress, packet.source, server)
	if !reserved {
		rangedPort, isRanged := portCapability[PortWithSelectorRange](verdict.Port)
		if isRanged && rangedPort.ExpandSelectorRanges(packet.protocol) {
			reservation, reserved = nat.reserveForPort(s.dispatcher, verdict.Port, packet.protocol, portAddress, packet.source, server)
		}
		if !reserved {
			return nil, createFlowExhausted
		}
	}
	published := false
	defer func() {
		if !published { nat.cancelReservation(packet.protocol, reservation) }
	}()
	var udpTimeout time.Duration
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		udpTimeout = verdict.UDPTimeout
	}
	flow := &forwardFlow{
		ownership: owned.Ownership,
		attachment: attachment,
		nat:                      nat,
		owner:                    s,
		effectiveMTU:             effectiveMTU,
		protocol:                 packet.protocol,
		udpTimeout:               udpTimeout,
		clientAddress:            packet.source.Addr(),
		clientSelector:           packet.source.Port(),
		clientDestinationAddress: clientDestinationAddress,
		clientDestinationPort:    clientDestinationPort,
		serverAddress:            serverAddress,
		dnatAddress:              serverAddress != clientDestinationAddress,
		dnatPort:                 serverPort != clientDestinationPort && !isICMP,
	}
	flow.forwardRule = rewriteRule{
		sourceAddress:     addrToTCPIP(portAddress),
		rewriteSourcePort: true,
	}
	if flow.dnatAddress {
		flow.forwardRule.destinationAddress = addrToTCPIP(serverAddress)
	}
	if flow.dnatPort {
		flow.forwardRule.destinationPort = serverPort
		flow.forwardRule.rewriteDestinationPort = true
	}
	flow.reverseRule = rewriteRule{
		destinationAddress:     addrToTCPIP(flow.clientAddress),
		destinationPort:        flow.clientSelector,
		rewriteDestinationPort: true,
	}
	if flow.dnatAddress {
		flow.reverseRule.sourceAddress = addrToTCPIP(clientDestinationAddress)
	}
	if flow.dnatPort {
		flow.reverseRule.sourcePort = clientDestinationPort
		flow.reverseRule.rewriteSourcePort = true
	}
	if verdict.NewTracker != nil {
		flow.tracker = verdict.NewTracker()
		if flow.tracker != nil {
			flow.tracker.AttachFlow(flow)
		}
	}
	nat.publish(flow, reservation)
	published = true
	owned.Ownership = nil
	keepAttachment = true
	return flow, createFlowOK
}

func (d *ForwardDispatcher) natFor(port Port, ownership FlowOwnership) *attachmentUse {
	for {
		d.portsAccess.Lock()
		if d.closed.Load() { d.portsAccess.Unlock(); return nil }
		if existing := d.ports[port]; existing != nil {
			ready := existing.ready
			detaching := existing.detaching
			d.portsAccess.Unlock()
			if detaching {
				<-existing.completion
				if existing.detachErr != nil { return nil }
				continue
			}
			<-ready
			if !existing.attached || existing.failed { return nil }
			use, err := existing.retainUse()
			if err != nil { return nil }
			return use
		}
		// Reserve identity only; never call a Port under this lock.
		r := &portReturn{port: port, dispatcher: d, ready: make(chan struct{}), detached: make(chan struct{}), completion: make(chan struct{}), fragmentStop: make(chan struct{}), fragmentDone: make(chan struct{}), fragments: fragmentTable{entries: make(map[fragmentKey]*fragmentEntry)}}
		d.ports[port] = r
		d.portsAccess.Unlock()
		var err error
		panicked := false
		func() {
			defer func() { if recover() != nil { panicked = true } }()
			if ownership != nil { r.ownership, err = ownership.RetainPort(port) }
			if err == nil {
				r.nat = acquirePortNAT(port)
				r.gate.owner, r.gate.target = r.ownership, r
				if d.returnTarget != nil { r.gate.target = d.returnTarget }
				err = port.AttachReturn(&r.gate)
			}
		}()
		if panicked {
			// Attach may have copied the callback before panicking. Seal it and
			// retain every known lease/NAT reservation; neither retry native
			// detach nor infer that an unreturned ownership token never existed.
			r.gate.seal()
			d.portsAccess.Lock()
			r.failed, r.detaching = true, true
			r.attached = r.nat != nil
			r.detachErr = errAttachmentPanic
			close(r.ready)
			close(r.fragmentDone) // no fragment worker was started
			d.portsAccess.Unlock()
			go func() { r.gate.join(); close(r.completion) }()
			return nil
		}
		d.portsAccess.Lock()
		if err != nil && r.nat == nil {
			delete(d.ports, port)
		} else { r.attached = true; r.failed = err != nil }
		close(r.ready)
		d.portsAccess.Unlock()
		if err != nil {
			if r.nat != nil { close(r.fragmentDone); d.detachIdle(r) } else if r.ownership != nil { r.ownership.Release() }
			d.logger.Trace(E.Cause(err, "attach return path"))
			return nil
		}
		go r.expireFragments()
		if d.closed.Load() { d.detachIdle(r); return nil }
		use, err := r.retainUse()
		if err != nil { d.detachIdle(r); return nil }
		if r.ownership != nil {
			go func() {
				select { case <-r.ownership.Retiring(): d.detachIdle(r); case <-r.detached: }
			}()
		}
		return use
	}
}

func (s *ForwardStage) forwardToPort(flow *forwardFlow, packet *forwardPacket, raw []byte, meta *ForwardFrameMeta) {
	effectiveMTU := flow.effectiveMTU
	if meta != nil {
		meta.completeChecksum(raw)
		if meta.gsoSize != 0 && packet.protocol == uint8(header.TCPProtocolNumber) {
			headerLength := len(raw) - len(packet.transport) + int(header.TCP(packet.transport).DataOffset())
			offloadMTU := uint32(headerLength) + uint32(meta.gsoSize)
			if effectiveMTU == 0 || offloadMTU < effectiveMTU {
				effectiveMTU = offloadMTU
			}
		}
	}
	if effectiveMTU != 0 && uint32(len(raw)) > effectiveMTU {
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if flow.tracker != nil {
				flow.tracker.CountForward(len(raw))
			}
			rewriteForward(flow, packet)
			s.resegmentTCP(flow, packet, raw, effectiveMTU)
			return
		}
		if packet.ipVersion == 4 {
			ipHdr := header.IPv4(packet.network)
			if ipHdr.Flags()&header.IPv4FlagDontFragment == 0 {
				if flow.tracker != nil {
					flow.tracker.CountForward(len(raw))
				}
				rewriteForward(flow, packet)
				fragments, ok := fragmentIPv4Packet(ipHdr, flow.effectiveMTU)
				if ok {
					for _, fragment := range fragments {
						s.stagePort(flow, fragment)
					}
				}
				return
			}
		}
		reply := buildICMPError(packet, ICMPErrorPacketTooBig, flow.effectiveMTU, s.writeback.ReturnHeadroom())
		s.access.Lock()
		s.writebackBatch = append(s.writebackBatch, reply)
		s.access.Unlock()
		return
	}
	if flow.tracker != nil {
		flow.tracker.CountForward(len(raw))
	}
	rewriteForward(flow, packet)
	if meta != nil {
		raw = s.copyForStage(raw)
	}
	s.stagePort(flow, raw)
}

func (s *ForwardStage) copyForStage(raw []byte) []byte {
	staged, _ := s.reserveSegments(1, len(raw))
	copy(staged[0], raw)
	return staged[0]
}

func rewriteForward(flow *forwardFlow, packet *forwardPacket) {
	if packet.isTCPSyn() {
		applyRewriteRaw(packet, &flow.forwardRule)
		clampTCPMSS(packet, flow.effectiveMTU)
		recomputeChecksums(packet)
	} else {
		applyRewrite(packet, &flow.forwardRule)
	}
}

func (s *ForwardStage) stagePort(flow *forwardFlow, packet []byte) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.dispatcher.closed.Load() { return }
	for index := range s.ports {
		if s.ports[index].attachment.returnPath == flow.attachment.returnPath { s.ports[index].packets = append(s.ports[index].packets, slices.Clone(packet)); return }
	}
	use, err := flow.attachment.returnPath.retainUse()
	if err != nil { return }
	s.ports = append(s.ports, stagedPort{attachment: use, packets: [][]byte{slices.Clone(packet)}})
}

func (s *ForwardStage) stageReject(packet *forwardPacket, raw []byte, meta *ForwardFrameMeta) {
	if meta != nil {
		meta.completeChecksum(raw)
	}
	reply, ok := buildReject(packet, s.writeback.ReturnHeadroom())
	if ok {
		s.access.Lock()
		s.writebackBatch = append(s.writebackBatch, reply)
		s.access.Unlock()
	}
}

func (d *ForwardDispatcher) ResetNetwork() {
	if d == nil {
		return
	}
	d.resetGeneration.Add(1)
}

func (s *ForwardStage) Flush() {
	if s == nil { return }
	d := s.dispatcher
	now := d.now()
	s.access.Lock()
	generation := d.resetGeneration.Load()
	if s.resetSeen != generation {
		s.resetSeen = generation
		for key, entry := range s.table { s.removeEntry(key, entry, FlowCloseReset) }
	}
	queued := s.ports
	s.ports = nil // No reusable empty raw-NAT entries survive retirement.
	writeback := s.writebackBatch
	s.writebackBatch = nil
	if now-s.lastSweep >= int64(flowSweepInterval) { s.lastSweep = now; s.sweep(now) }
	s.access.Unlock()
	s.drainRetired()
	for _, staged := range queued {
		if !d.closed.Load() {
			if err := staged.attachment.returnPath.port.WritePackets(staged.packets); err != nil { d.logger.Trace(E.Cause(err, "forward packets")) }
		}
		staged.attachment.release() // Also after an in-flight WritePackets returns.
	}
	if !d.closed.Load() && len(writeback) > 0 {
		if err := s.writeback.WriteReturnPackets(writeback); err != nil { d.logger.Trace(E.Cause(err, "write back packets")) }
	}

}

func (s *ForwardStage) sweepDue() (time.Duration, bool) {
	if s == nil {
		return 0, false
	}
	s.access.Lock()
	count := len(s.table)
	s.access.Unlock()
	if count == 0 {
		return 0, false
	}
	return max(time.Duration(s.lastSweep+int64(flowSweepInterval)-s.dispatcher.now()), 0), true
}

func entryExpired(entry *flowEntry, now int64) bool {
	if now <= entry.deadline {
		return false
	}
	if entry.action == ActionFlow {
		lastReverse := entry.flow.lastReverse.Load()
		reverseDeadline := lastReverse + int64(entry.idle)
		if lastReverse != 0 && now <= reverseDeadline {
			entry.deadline = reverseDeadline
			return false
		}
	}
	return true
}

func tombstoneEntry(entry *flowEntry, now int64) {
	entry.action = ActionDrop
	entry.idle = flowTombstoneTimeout
	entry.deadline = now + int64(entry.idle)
}

type retiredFlowEntry struct { entry *flowEntry; reason FlowCloseReason }

func (s *ForwardStage) removeEntry(key flowKey, entry *flowEntry, reason FlowCloseReason) {
	delete(s.table, key)
	s.retired = append(s.retired, retiredFlowEntry{entry, reason})
}

func (s *ForwardStage) releaseFlow(flow *forwardFlow, reason FlowCloseReason) {
	if reason == FlowCloseTimeout && flow.finForward.Load() && flow.finReverse.Load() { reason = FlowCloseFinished }
	flow.close(reason)
	flow.nat.release(flow)
	releaseFlow(flow.ownership)
	flow.attachment.release()
}

func (s *ForwardStage) drainRetired() {
	s.access.Lock()
	retired := s.retired
	s.retired = nil
	s.access.Unlock()
	for _, item := range retired {
		item.entry.verdict.Release()
		if item.entry.flow != nil { s.releaseFlow(item.entry.flow, item.reason) }
	}
}

func (s *ForwardStage) insertEntry(key flowKey, entry *flowEntry, now int64) {
	if previous := s.table[key]; previous != nil && previous != entry { s.removeEntry(key, previous, FlowCloseReset) }
	if len(s.table) >= max(flowTableCapacity/int(s.dispatcher.stageCount.Load()), flowStageCapacity) {
		s.evictEntries(now)
	}
	s.table[key] = entry
}

func (s *ForwardStage) evictEntries(now int64) {
	var (
		freed     int
		visited   int
		oldestKey flowKey
		oldest    *flowEntry
	)
	for key, entry := range s.table {
		if entryExpired(entry, now) {
			s.removeEntry(key, entry, FlowCloseTimeout)
			freed++
		} else if oldest == nil || entry.deadline < oldest.deadline {
			oldestKey = key
			oldest = entry
		}
		visited++
		if visited >= flowSweepLimit {
			break
		}
	}
	if freed == 0 && oldest != nil {
		s.removeEntry(oldestKey, oldest, FlowCloseReset)
	}
}

func (s *ForwardStage) sweep(now int64) {
	visited := 0
	for key, entry := range s.table {
		if entry.action == ActionFlow && entry.flow.closed.Load() {
			tombstoneEntry(entry, now)
		} else if entryExpired(entry, now) {
			s.removeEntry(key, entry, FlowCloseTimeout)
		}
		visited++
		if visited >= flowSweepLimit {
			break
		}
	}
}

func isICMPProtocol(protocol uint8) bool {
	return protocol == uint8(header.ICMPv4ProtocolNumber) || protocol == uint8(header.ICMPv6ProtocolNumber)
}

type portReturn struct {
 port Port // exact logical attachment, independent of the physical NAT key
	ownership PortOwnership
	gate sealedReturn
	ready chan struct{}
	detached chan struct{}
	completion chan struct{}
	detachErr error
	attached bool
	failed bool
	detaching bool
	fragmentStop chan struct{}
	fragmentDone chan struct{}
	uses int
	dispatcher *ForwardDispatcher
	nat        *portNAT
	fragments  fragmentTable
}

func (r *portReturn) ReturnHeadroom() int {
	return r.dispatcher.writeback.ReturnHeadroom()
}

type returnDecision uint8

const (
	returnPass returnDecision = iota
	returnWrite
	returnDrop
)

type returnBatch struct {
	writeback ForwardWriteback
	packets   [][]byte
}

func (r *portReturn) ReturnPackets(packets [][]byte) [][]byte {
	if r.dispatcher.closed.Load() {
		return packets
	}
	headroom := r.dispatcher.writeback.ReturnHeadroom()
	now := r.dispatcher.now()
	unconsumed := packets[:0]
	var batches []returnBatch
	var uses []*forwardUse
	defer func() { for _, use := range uses { use.release() } }()
	for _, raw := range packets {
		decision, writeback, use := r.classifyReturn(raw, headroom, now)
		if use != nil { uses = append(uses, use) }
		switch decision {
		case returnWrite:
			index := slices.IndexFunc(batches, func(batch returnBatch) bool { return batch.writeback == writeback })
			if index < 0 {
				batches = append(batches, returnBatch{writeback: writeback})
				index = len(batches) - 1
			}
			batches[index].packets = append(batches[index].packets, raw)
		case returnDrop:
		default:
			unconsumed = append(unconsumed, raw)
		}
	}
	for _, batch := range batches {
		err := batch.writeback.WriteReturnPackets(batch.packets)
		if err != nil {
			r.dispatcher.logger.Trace(E.Cause(err, "write return packets"))
		}
	}
	return unconsumed
}

func (r *portReturn) classifyReturn(raw []byte, headroom int, now int64) (returnDecision, ForwardWriteback, *forwardUse) {
	if len(raw) < headroom+header.IPv4MinimumSize { return returnPass, nil, nil }
	parsed, ok := parseForwardPacket(raw[headroom:])
	if !ok { return returnPass, nil, nil }
	if parsed.fragment { return r.classifyFragment(&parsed, len(raw)-headroom, now) }
	if !parsed.hasFlow {
		if parsed.isICMPError() {
			use := r.returnICMPError(&parsed)
			if use != nil { return returnWrite, use.flow.owner.writeback, use }
		}
		return returnPass, nil, nil
	}
	use, rule := r.matchReverse(&parsed)
	if use == nil { return returnPass, nil, nil }
	flow := use.flow
	if flow.closed.Load() { return returnDrop, nil, use }
	if flow.tracker != nil { flow.tracker.CountReverse(len(raw)-headroom) }
	flow.observeReverse(&parsed, now)
	if parsed.isTCPSyn() { applyRewriteRaw(&parsed, rule); clampTCPMSS(&parsed, flow.effectiveMTU); recomputeChecksums(&parsed) } else { applyRewrite(&parsed, rule) }
	return returnWrite, flow.owner.writeback, use
}

// A shared physical namespace must deliver through the exact logical attachment.
// In particular, the fragment entry retains this same attachment's forwardUse,
// preventing its callback and fragment table from retiring before continuation.
func (r *portReturn) ownsReturnUse(use *forwardUse) bool {
 return use != nil && use.flow != nil && use.flow.attachment != nil && use.flow.attachment.returnPath == r
}

func (r *portReturn) matchReverse(parsed *forwardPacket) (*forwardUse, *rewriteRule) {
	key := parsed.flowKey()
	use := r.nat.lookupOwned(key)
	if use != nil {
		if use.flow.owner.dispatcher != r.dispatcher || !r.ownsReturnUse(use) { use.release(); return nil, nil }
		return use, &use.flow.reverseRule
	}
	if parsed.protocol != uint8(header.UDPProtocolNumber) { return nil, nil }
	mapping, use := r.nat.lookupMappingOwned(key.destination.Addr(), key.destination.Port(), key.source.Addr())
	if mapping == nil { return nil, nil }
	if mapping.key.dispatcher != r.dispatcher || !r.ownsReturnUse(use) { use.release(); return nil, nil }
	return use, &mapping.reverseRule
}

func (r *portReturn) returnICMPError(parsed *forwardPacket) *forwardUse {
	inner, ok := parsed.icmpErrorInner()
	if !ok {
		return nil
	}
	embedded, parsedInner := parseEmbedded(inner)
	if !parsedInner {
		return nil
	}
	use := r.nat.lookupOwned(embedded.flowKey().reversed())
	if use == nil { return nil }
	flow := use.flow
	if flow.owner.dispatcher != r.dispatcher || !r.ownsReturnUse(use) || flow.closed.Load() {
		use.release()
		return nil
	}
	rewriteEmbeddedSource(&embedded, addrToTCPIP(flow.clientAddress), flow.clientSelector, true)
	if flow.dnatAddress || flow.dnatPort {
		rewriteEmbeddedDestination(&embedded, addrToTCPIP(flow.clientDestinationAddress), flow.clientDestinationPort, flow.dnatPort)
	}
	sourceAddress, destinationAddress := parsed.addressSlices()
	copy(destinationAddress, flow.clientAddress.AsSlice())
	if parsed.source.Addr() == flow.serverAddress {
		copy(sourceAddress, flow.clientDestinationAddress.AsSlice())
	}
	recomputeChecksums(parsed)
	return use
}

func (d *ForwardDispatcher) sweepIdle(now int64) {
	d.stagesAccess.Lock()
	stages := slices.Clone(d.stages)
	d.stagesAccess.Unlock()
	for _, stage := range stages {
		stage.access.Lock()
		stage.sweep(now)
		stage.access.Unlock()
		stage.drainRetired()
	}
}
