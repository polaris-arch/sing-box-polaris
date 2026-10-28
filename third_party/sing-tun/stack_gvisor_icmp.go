//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/header/parse"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type ICMPForwarder struct {
	stack   *stack.Stack
	handler Handler
	logger  logger.Logger

	returnPath icmpForwarderReturn

	flowAccess    sync.Mutex
	flows         map[icmpFlowKey]*icmpFlow
	lastSweep     time.Time
	attachments *ForwardDispatcher
	stop chan struct{}
	done chan struct{}
	closeOnce sync.Once
}

type icmpFlowKey struct {
	v6          bool
	source      netip.Addr
	destination netip.Addr
	identifier  uint16
}

type icmpFlow struct {
	ownership FlowOwnership
	attachment *attachmentUse
	port     Port
	tracker  FlowTracker
	deadline time.Time
	closed   atomic.Bool
}

func (f *icmpFlow) close(reason FlowCloseReason) {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	if f.tracker != nil {
		f.tracker.CloseFlow(reason)
	}
}

func (f *icmpFlow) CloseFlow() {
	f.close(FlowCloseReset)
}

func NewICMPForwarder(stack *stack.Stack, handler Handler, logger logger.Logger) *ICMPForwarder {
	forwarder := &ICMPForwarder{
		stack:         stack,
		handler:       handler,
		logger:        logger,
		flows:         make(map[icmpFlowKey]*icmpFlow),

	}
	forwarder.stop, forwarder.done = make(chan struct{}), make(chan struct{})
	forwarder.returnPath.forwarder = forwarder
	forwarder.attachments = NewForwardDispatcher(handler, nil, logger, UDPNatOptions{}, defaultICMPTimeout)
	forwarder.attachments.returnTarget = &forwarder.returnPath
	go forwarder.expireLoop()
	return forwarder
}

func (f *ICMPForwarder) Purge() {
	f.flowAccess.Lock()
	flows := f.flows
	f.flows = make(map[icmpFlowKey]*icmpFlow)
	f.flowAccess.Unlock()
	for _, flow := range flows { flow.remove(FlowCloseReset) }
}

func (f *ICMPForwarder) Close() error {
	f.returnPath.closed.Store(true)
	f.closeOnce.Do(func() { close(f.stop) })
	f.Purge()
	f.attachments.Close()
	return nil
}

func (f *icmpFlow) remove(reason FlowCloseReason) {
	f.close(reason)
	releaseFlow(f.ownership)
	f.attachment.release()
}

type icmpUse struct { flow *icmpFlow; owner FlowOwnership; attachment *attachmentUse }
func (f *icmpFlow) retain() (*icmpUse, error) {
	owner, err := retainFlow(f.ownership)
	if err != nil { return nil, err }
	attachment, err := f.attachment.returnPath.retainUse()
	if err != nil { releaseFlow(owner); return nil, err }
	return &icmpUse{flow: f, owner: owner, attachment: attachment}, nil
}
func (u *icmpUse) release() {
	if u == nil { return }
	releaseFlow(u.owner)
	u.attachment.release()
}

func (f *ICMPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		icmpHdr := header.ICMPv4(pkt.TransportHeader().Slice())
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
			return false
		}
		identifier := icmpHdr.Ident()
		key := icmpFlowKey{
			source:      AddrFromAddress(ipHdr.SourceAddress()),
			destination: AddrFromAddress(ipHdr.DestinationAddress()),
			identifier:  identifier,
		}
		if f.forwardCached(key, pkt) {
			return true
		}
		verdict := f.handler.JudgeFlow(
			uint8(header.ICMPv4ProtocolNumber),
			netip.AddrPortFrom(key.source, identifier),
			netip.AddrPortFrom(key.destination, identifier),
			nil,
		)
		defer verdict.Release()
		switch verdict.Action {
		case ActionReject, ActionDrop:
			return true
		case ActionFlow, ActionBypass:
			if f.installFlow(key, verdict, pkt) {
				return true
			}
		}
		icmpHdr.SetType(header.ICMPv4EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], pkt.Data().Checksum()))
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		outgoingEP, gErr := f.stack.GetNetworkEndpoint(DefaultNIC, header.IPv4ProtocolNumber)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "get IPv4 network endpoint"))
			return true
		}
		route, gErr := f.stack.FindRoute(
			DefaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv4ProtocolNumber,
			false,
		)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "find IPv4 route"))
			return true
		}
		defer route.Release()
		outgoingEP.(ipv4.ExportedEndpoint).WritePacketDirect(route, pkt)
		return true
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Slice())
		icmpHdr := header.ICMPv6(pkt.TransportHeader().Slice())
		if icmpHdr.Type() != header.ICMPv6EchoRequest {
			return false
		}
		if icmpHdr.Code() != 0 {
			// The IPv6 built-in echo reply path lacks the LocalAddressTemporary
			// check its IPv4 sibling has, so returning false would make the stack
			// reply on behalf of arbitrary forwarded destinations.
			return true
		}
		identifier := icmpHdr.Ident()
		key := icmpFlowKey{
			v6:          true,
			source:      AddrFromAddress(ipHdr.SourceAddress()),
			destination: AddrFromAddress(ipHdr.DestinationAddress()),
			identifier:  identifier,
		}
		if f.forwardCached(key, pkt) {
			return true
		}
		verdict := f.handler.JudgeFlow(
			uint8(header.ICMPv6ProtocolNumber),
			netip.AddrPortFrom(key.source, identifier),
			netip.AddrPortFrom(key.destination, identifier),
			nil,
		)
		defer verdict.Release()
		switch verdict.Action {
		case ActionReject, ActionDrop:
			return true
		case ActionFlow, ActionBypass:
			if f.installFlow(key, verdict, pkt) {
				return true
			}
		}
		icmpHdr.SetType(header.ICMPv6EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHdr,
			Src:         ipHdr.SourceAddress(),
			Dst:         ipHdr.DestinationAddress(),
			PayloadCsum: pkt.Data().Checksum(),
			PayloadLen:  pkt.Data().Size(),
		}))
		outgoingEP, gErr := f.stack.GetNetworkEndpoint(DefaultNIC, header.IPv6ProtocolNumber)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "get IPv6 network endpoint"))
			return true
		}
		route, gErr := f.stack.FindRoute(
			DefaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv6ProtocolNumber,
			false,
		)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "find IPv6 route"))
			return true
		}
		defer route.Release()
		outgoingEP.(ipv6.ExportedEndpoint).WritePacketDirect(route, pkt)
		return true
	}
}

func (f *ICMPForwarder) forwardCached(key icmpFlowKey, pkt *stack.PacketBuffer) bool {
	use := f.lookupFlow(key)
	if use == nil { return false }
	defer use.release()
	f.writeToPort(use.flow, pkt)
	return true
}

func (f *ICMPForwarder) installFlow(key icmpFlowKey, verdict FlowVerdict, pkt *stack.PacketBuffer) bool {
	if verdict.Port == nil || f.returnPath.closed.Load() { return false }
	owned, err := verdict.CloneForDelivery()
	if err != nil { return false }
	defer owned.Release()
	attachment := f.attachments.natFor(verdict.Port, owned.Ownership)
	if attachment == nil { return false }
	keep := false
	defer func() { if !keep { attachment.release() } }()
	inet4Address, inet6Address := verdict.Port.PortAddresses()
	portAddress := inet4Address
	if key.v6 { portAddress = inet6Address }
	if !portAddress.IsValid() || !portAddress.IsUnspecified() { return false }
	flow := &icmpFlow{port: verdict.Port, ownership: owned.Ownership, attachment: attachment, deadline: time.Now().Add(defaultICMPTimeout)}
	if verdict.NewTracker != nil { flow.tracker = verdict.NewTracker() }
	// No tracker or port call is allowed under flowAccess.
	if flow.tracker != nil { flow.tracker.AttachFlow(flow) }
	f.flowAccess.Lock()
	if f.returnPath.closed.Load() {
		f.flowAccess.Unlock()
		flow.close(FlowCloseReset)
		return false
	}
	if existing := f.flows[key]; existing != nil {
		use, retainErr := existing.retain()
		f.flowAccess.Unlock()
		flow.close(FlowCloseReset)
		if retainErr != nil { return false }
		defer use.release()
		f.writeToPort(use.flow, pkt)
		return true
	}
	f.flows[key] = flow
	use, retainErr := flow.retain()
	owned.Ownership = nil
	keep = true
	f.flowAccess.Unlock()
	if retainErr != nil { return true }
	defer use.release()
	f.writeToPort(flow, pkt)
	return true
}

func (f *ICMPForwarder) writeToPort(flow *icmpFlow, pkt *stack.PacketBuffer) {
	networkSlice := pkt.NetworkHeader().Slice()
	transportSlice := pkt.TransportHeader().Slice()
	dataSlice := pkt.Data().AsRange().ToSlice()
	packetSlice := make([]byte, 0, len(networkSlice)+len(transportSlice)+len(dataSlice))
	packetSlice = append(packetSlice, networkSlice...)
	packetSlice = append(packetSlice, transportSlice...)
	packetSlice = append(packetSlice, dataSlice...)
	if flow.tracker != nil {
		flow.tracker.CountForward(len(packetSlice))
	}
	err := flow.port.WritePackets([][]byte{packetSlice})
	if err != nil {
		f.logger.Trace(E.Cause(err, "forward ICMP packet"))
	}
}

func (f *ICMPForwarder) lookupFlow(key icmpFlowKey) *icmpUse {
	f.flowAccess.Lock()
	flow := f.flows[key]
	if flow == nil || f.returnPath.closed.Load() { f.flowAccess.Unlock(); return nil }
	now := time.Now()
	if flow.closed.Load() || now.After(flow.deadline) {
		delete(f.flows, key)
		f.flowAccess.Unlock()
		flow.remove(FlowCloseTimeout)
		return nil
	}
	flow.deadline = now.Add(defaultICMPTimeout)
	use, err := flow.retain()
	f.flowAccess.Unlock()
	if err != nil { return nil }
	return use
}

func (f *ICMPForwarder) expireFlows(now time.Time) {
	f.flowAccess.Lock()
	var expired []*icmpFlow
	for key, flow := range f.flows {
		if flow.closed.Load() || now.After(flow.deadline) { delete(f.flows, key); expired = append(expired, flow) }
	}
	f.flowAccess.Unlock()
	for _, flow := range expired { flow.remove(FlowCloseTimeout) }
}

type icmpForwarderReturn struct {
	forwarder *ICMPForwarder
	closed    atomic.Bool
}

func (r *icmpForwarderReturn) ReturnHeadroom() int {
	return 0
}

func (r *icmpForwarderReturn) ReturnPackets(packets [][]byte) [][]byte {
	if r.closed.Load() {
		return packets
	}
	unconsumed := packets[:0]
	for _, packet := range packets {
		if !r.forwarder.returnPacket(packet) {
			unconsumed = append(unconsumed, packet)
		}
	}
	return unconsumed
}

func (f *ICMPForwarder) returnPacket(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.TransportProtocol() != header.ICMPv4ProtocolNumber || len(ipHdr.Payload()) < header.ICMPv4MinimumSize {
			return false
		}
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		var key icmpFlowKey
		switch icmpHdr.Type() {
		case header.ICMPv4EchoReply:
			key = icmpFlowKey{
				source:      AddrFromAddress(ipHdr.DestinationAddress()),
				destination: AddrFromAddress(ipHdr.SourceAddress()),
				identifier:  icmpHdr.Ident(),
			}
		case header.ICMPv4TimeExceeded, header.ICMPv4DstUnreachable:
			inner := icmpHdr.Payload()
			if len(inner) < header.IPv4MinimumSize {
				return false
			}
			innerIPHdr := header.IPv4(inner)
			innerHeaderLength := int(innerIPHdr.HeaderLength())
			if innerHeaderLength < header.IPv4MinimumSize || len(inner) < innerHeaderLength+header.ICMPv4MinimumSize {
				return false
			}
			if innerIPHdr.TransportProtocol() != header.ICMPv4ProtocolNumber {
				return false
			}
			innerICMPHdr := header.ICMPv4(inner[innerHeaderLength:])
			key = icmpFlowKey{
				source:      AddrFromAddress(innerIPHdr.SourceAddress()),
				destination: AddrFromAddress(innerIPHdr.DestinationAddress()),
				identifier:  innerICMPHdr.Ident(),
			}
		default:
			return false
		}
		use := f.lookupFlow(key)
		if use == nil { return false }
		defer use.release()
		flow := use.flow
		if flow.tracker != nil {
			flow.tracker.CountReverse(len(packet))
		}
		return f.writeBack(packet, header.IPv4ProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress())
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.TransportProtocol() != header.ICMPv6ProtocolNumber || len(ipHdr.Payload()) < header.ICMPv6MinimumSize {
			return false
		}
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		if icmpHdr.Type() != header.ICMPv6EchoReply {
			return false
		}
		key := icmpFlowKey{
			v6:          true,
			source:      AddrFromAddress(ipHdr.DestinationAddress()),
			destination: AddrFromAddress(ipHdr.SourceAddress()),
			identifier:  icmpHdr.Ident(),
		}
		use := f.lookupFlow(key)
		if use == nil { return false }
		defer use.release()
		flow := use.flow
		if flow.tracker != nil {
			flow.tracker.CountReverse(len(packet))
		}
		return f.writeBack(packet, header.IPv6ProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress())
	default:
		return false
	}
}

func (f *ICMPForwarder) writeBack(packet []byte, protocol tcpip.NetworkProtocolNumber, localAddress tcpip.Address, remoteAddress tcpip.Address) bool {
	route, gErr := f.stack.FindRoute(DefaultNIC, localAddress, remoteAddress, protocol, false)
	if gErr != nil {
		f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "find route for ICMP reply"))
		return true
	}
	defer route.Release()
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	defer packetBuffer.DecRef()
	if protocol == header.IPv4ProtocolNumber {
		parse.IPv4(packetBuffer)
	} else {
		parse.IPv6(packetBuffer)
	}
	gErr = route.WritePacketDirect(packetBuffer)
	if gErr != nil {
		f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "write ICMP reply"))
	}
	return true
}

func (f *ICMPForwarder) expireLoop() {
	defer close(f.done)
	ticker := time.NewTicker(fragmentSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C: f.expireFlows(now)
		case <-f.stop: return
		}
	}
}

func (f *ICMPForwarder) WaitDetached(ctx context.Context) error {
	if err := f.attachments.WaitDetached(ctx); err != nil { return err }
	select { case <-f.done: return nil; case <-ctx.Done(): return ctx.Err() }
}
