package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// cachedVerdict forks while holding the same table lock that removes the cache
// reference. This is used where an OS/gVisor carrier cannot carry a Go context.
func (d *ForwardDispatcher) cachedVerdict(protocol uint8, source, destination netip.AddrPort) (FlowVerdict, bool) {
	if d == nil { return FlowVerdict{}, false }
	if d.closed.Load() { return FlowVerdict{Action: ActionDrop}, true }
	d.stagesAccess.Lock()
	stages := append([]*ForwardStage(nil), d.stages...)
	d.stagesAccess.Unlock()
	key := flowKey{protocol: protocol, source: source, destination: destination}
	for _, stage := range stages {
		stage.access.Lock()
		entry := stage.table[key]
		if entry != nil && entry.action == ActionAccept && !entryExpired(entry, d.now()) {
			verdict, err := entry.verdict.CloneForDelivery()
			stage.access.Unlock()
			if err != nil { return FlowVerdict{Action: ActionDrop}, true }
			return verdict, true
		}
		stage.access.Unlock()
	}
	return FlowVerdict{}, false
}

type cachedFlowHandler struct { Handler; dispatcher *ForwardDispatcher }
type cachedDNSFlowHandler struct { *cachedFlowHandler; dns DNSPacketHandlerEx }

func (d *ForwardDispatcher) fallbackHandler() Handler {
	if d == nil { return nil }
	base := &cachedFlowHandler{Handler: d.handler, dispatcher: d}
	if dns, ok := d.handler.(DNSPacketHandlerEx); ok { return &cachedDNSFlowHandler{base, dns} }
	return base
}

func (h *cachedFlowHandler) JudgeFlow(protocol uint8, source, destination netip.AddrPort, first []byte) FlowVerdict {
	if verdict, ok := h.dispatcher.cachedVerdict(protocol, source, destination); ok { return verdict }
	return h.Handler.JudgeFlow(protocol, source, destination, first)
}

func (h *cachedDNSFlowHandler) NewDNSPacketEx(ctx context.Context, payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	h.dns.NewDNSPacketEx(ctx, payload, source, destination, writer)
}

type ownedSystemConn struct { net.Conn; ownership FlowOwnership; once sync.Once }
func (c *ownedSystemConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { releaseFlow(c.ownership) })
	return err
}

type ownedPacketWriter struct { N.PacketWriter; ownership flowOwnershipSlot }
func (w *ownedPacketWriter) retainFlowOwnership() (FlowOwnership, error) { return w.ownership.retain() }
func (w *ownedPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	owner, err := w.ownership.retain()
	if err != nil { buffer.Release(); return err }
	defer releaseFlow(owner)
	return w.PacketWriter.WritePacket(buffer, destination)
}
func (w *ownedPacketWriter) Close() error {
	err := common.Close(w.PacketWriter)
	w.ownership.release()
	return err
}
