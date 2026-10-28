//go:build with_tailscale

package tailscale

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	tsTUN "github.com/sagernet/tailscale/net/tstun"
	"github.com/sagernet/tailscale/types/ipproto"
	"github.com/sagernet/tailscale/wgengine/filter"
)

func (t *Endpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (t *Endpoint) PortAddresses() (netip.Addr, netip.Addr) {
	if t.runtime != nil {
		child, leave, err := t.runtimeChild(true)
		if err != nil {
			return netip.Addr{}, netip.Addr{}
		}
		defer leave()
		return child.PortAddresses()
	}

	if !t.started.Load() {
		return netip.Addr{}, netip.Addr{}
	}
	return t.server.TailscaleIPs()
}

func (t *Endpoint) PortMTU() uint32 {
	if t.runtime != nil {
		child, leave, err := t.runtimeChild(true)
		if err != nil {
			return 0
		}
		defer leave()
		return child.PortMTU()
	}

	if t.systemInterface {
		return t.systemInterfaceMTU
	}
	return uint32(tsTUN.DefaultTUNMTU())
}

func (t *Endpoint) UpstreamPort() any {
	if t.runtime != nil {
		return t
	}
	if !t.started.Load() {
		return nil
	}
	return t.stack
}

func (t *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) (verdict tun.FlowVerdict) {
	child := t
	routeRouter := t.router
	inboundTag := t.Tag()
	var b *runtimeEndpointBinding
	var owned context.Context
	var release func()
	var err error
	if t.runtime != nil {
		child, owned, release, err = t.runtimeBoundChild(context.Background())
		if err == nil {
			t.runtime.mu.Lock()
			b = t.runtime.binding
			t.runtime.mu.Unlock()
			routeRouter = b.router
			inboundTag = b.logical.Tag()
		}
	} else if t.runtimePhysical != nil {
		b, owned, release, err = t.runtimePhysical.bindingContext(context.Background(), true)
		if err == nil {
			routeRouter = b.router
			inboundTag = b.logical.Tag()
		}
	}
	if err != nil {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	if b != nil {
		defer func() {
			verdict.Ownership = &runtimeBindingFlow{inner: verdict.Ownership, binding: b, owned: owned, release: release}
		}()
	}
	return child.judgeFlowBound(routeRouter, inboundTag, network, source, destination, firstPacket)
}

func (t *Endpoint) judgeFlowBound(routeRouter adapter.Router, inboundTag string, network uint8, source, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	inet4Address, inet6Address := t.PortAddresses()
	if destination.Addr() == inet4Address || destination.Addr() == inet6Address {
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	if t.started.Load() {
		tsFilter := t.wgEngine.GetFilter()
		if tsFilter != nil {
			var (
				ipProto         ipproto.Proto
				destinationPort uint16
			)
			switch network {
			case uint8(header.TCPProtocolNumber):
				ipProto = ipproto.TCP
				destinationPort = destination.Port()
			case uint8(header.UDPProtocolNumber):
				ipProto = ipproto.UDP
				destinationPort = destination.Port()
			case uint8(header.ICMPv4ProtocolNumber):
				ipProto = ipproto.ICMPv4
			case uint8(header.ICMPv6ProtocolNumber):
				ipProto = ipproto.ICMPv6
			}
			switch tsFilter.Check(source.Addr(), destination.Addr(), destinationPort, ipProto) {
			case filter.Drop:
				return tun.FlowVerdict{Action: tun.ActionReject}
			case filter.DropSilently:
				return tun.FlowVerdict{Action: tun.ActionDrop}
			}
		}
	}
	return adapter.JudgeFlow(routeRouter, adapter.InboundContext{Inbound: inboundTag, InboundType: t.Type()}, network, source, destination, firstPacket)
}

func (t *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	t.NewDNSPacketEx(t.ctx, payload, source, destination, writer)
}

// NewDNSPacketEx forwards the borrowed packet admission synchronously.
// HijackDNSPacket owns the fork before asynchronous DNS work is published.
func (t *Endpoint) NewDNSPacketEx(ctx context.Context, payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	routeRouter := t.router
	inboundTag := t.Tag()
	if t.runtimePhysical != nil {
		b, owned, release, err := t.runtimePhysical.bindingContext(ctx, true)
		if err != nil {
			return
		}
		defer release()
		ctx = owned
		routeRouter = b.router
		inboundTag = b.logical.Tag()
	}

	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = inboundTag
	metadata.InboundType = t.Type()
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.Destination = destination
	metadata.Protocol = C.ProtocolDNS
	t.logger.InfoContext(ctx, "inbound DNS packet from ", source)
	routeRouter.HijackDNSPacket(ctx, payload, writer, metadata)
}

func (t *Endpoint) AttachReturn(returnPath tun.Return) error {
	if t.runtime != nil {
		child, leave, err := t.runtimeChild(true)
		if err != nil {
			return err
		}
		defer leave()
		return child.runtimePhysical.returns.attach(child, returnPath)
	}

	t.returnAccess.Lock()
	defer t.returnAccess.Unlock()
	if t.returnPath == returnPath {
		return nil
	}
	if t.returnPath != nil {
		return E.New("return path already attached")
	}
	err := t.wgEngine.SetReturnPath(returnPath)
	if err != nil {
		return err
	}
	t.returnPath = returnPath
	return nil
}

func (t *Endpoint) DetachReturn(returnPath tun.Return) error {
	if t.runtime != nil {
		child, leave, err := t.runtimeChild(true)
		if err != nil {
			return err
		}
		defer leave()
		return child.runtimePhysical.returns.detach(returnPath)
	}

	t.returnAccess.Lock()
	defer t.returnAccess.Unlock()
	if t.returnPath == returnPath {
		t.returnPath = nil
	}
	return nil
}

func (t *Endpoint) WritePackets(packets [][]byte) error {
	if t.runtime != nil {
		child, leave, err := t.runtimeChild(true)
		if err != nil {
			return err
		}
		defer leave()
		return child.WritePackets(packets)
	}

	if !t.started.Load() {
		return E.New("Tailscale is not ready yet")
	}
	t.requestResume()
	unmatched, err := t.wgEngine.InputPackets(packets)
	if err != nil || len(unmatched) == 0 {
		return err
	}
	t.returnAccess.Lock()
	returnPath := t.returnPath
	t.returnAccess.Unlock()
	if returnPath == nil {
		return nil
	}
	headroom := returnPath.ReturnHeadroom()
	inet4Address, inet6Address := t.PortAddresses()
	var replies [][]byte
	for _, packet := range unmatched {
		source := inet4Address
		if header.IPVersion(packet) == header.IPv6Version {
			source = inet6Address
		}
		reply, replyOk := tun.BuildICMPError(packet, tun.ICMPErrorNoRoute, source, 0, headroom)
		if replyOk {
			replies = append(replies, reply)
		}
	}
	if len(replies) > 0 {
		returnPath.ReturnPackets(replies)
	}
	return nil
}

var _ tun.DNSPacketHandlerEx = (*Endpoint)(nil)

func (t *Endpoint) WaitDetached(ctx context.Context) error {
	if t.runtime != nil {
		t.runtime.mu.Lock()
		b := t.runtime.binding
		t.runtime.mu.Unlock()
		if b == nil {
			return nil
		}
		select {
		case <-b.closeDone:
			return b.closeErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if t.stack == nil {
		return net.ErrClosed
	}
	return t.stack.WaitDetached(ctx)
}
