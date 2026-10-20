package shadowsocks

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/udpnat"
)

// The dependency capability is checked explicitly; packet ingress must never
// claim HOT readiness against the unpatched borrowed-context launch boundary.
func validateRuntimePacketContext() error {
	if !udpnat.RuntimePacketContextSupported() {
		return errors.New("Shadowsocks UDP session context retention is unavailable")
	}
	return nil
}

type runtimeUpstreamHandler struct {
	adapter.LegacyUpstreamHandlerAdapter
	runtime *inboundRuntime
}

func newRuntimeUpstreamHandler(runtime *inboundRuntime, handler adapter.LegacyUpstreamHandlerAdapter) adapter.LegacyUpstreamHandlerAdapter {
	if runtime == nil {
		return handler
	}
	return &runtimeUpstreamHandler{LegacyUpstreamHandlerAdapter: handler, runtime: runtime}
}

func (h *runtimeUpstreamHandler) RetainPacketContext(ctx context.Context) (func(context.Context) context.Context, func(), error) {
	owned, release, err := h.runtime.enter(ctx)
	if err != nil {
		return nil, nil, err
	}
	return func(final context.Context) context.Context { return adapter.ContextWithRuntimeOwnership(final, owned) }, release, nil
}

var _ listener.RuntimePacketHandler = (*Inbound)(nil)

func (h *Inbound) NewPacketContext(ctx context.Context, buffer *buf.Buffer, source M.Socksaddr) {
	ctx, release, err := h.runtime.enter(ctx)
	if err != nil {
		buffer.Release()
		return
	}
	defer release()
	// The pinned NAT helper retains only on the actual first-session launch.
	// Packet buffers are transferred to that helper; on parse failure they stay ours.
	err = h.service.NewPacket(ctx, &stubPacketConn{h.listener.PacketWriter()}, buffer, M.Metadata{Source: source})
	if err != nil {
		buffer.Release()
		h.logger.ErrorContext(ctx, E.Cause(err, "process packet from ", source))
	}
}

var _ listener.RuntimePacketHandler = (*MultiInbound)(nil)

func (h *MultiInbound) NewPacketContext(ctx context.Context, buffer *buf.Buffer, source M.Socksaddr) {
	ctx, release, err := h.runtime.enter(ctx)
	if err != nil {
		buffer.Release()
		return
	}
	defer release()
	// The pinned NAT helper retains only on the actual first-session launch.
	// Packet buffers are transferred to that helper; on parse failure they stay ours.
	err = h.service.NewPacket(ctx, &stubPacketConn{h.listener.PacketWriter()}, buffer, M.Metadata{Source: source})
	if err != nil {
		buffer.Release()
		h.logger.ErrorContext(ctx, E.Cause(err, "process packet from ", source))
	}
}

var _ listener.RuntimePacketHandler = (*RelayInbound)(nil)

func (h *RelayInbound) NewPacketContext(ctx context.Context, buffer *buf.Buffer, source M.Socksaddr) {
	ctx, release, err := h.runtime.enter(ctx)
	if err != nil {
		buffer.Release()
		return
	}
	defer release()
	// The pinned NAT helper retains only on the actual first-session launch.
	// Packet buffers are transferred to that helper; on parse failure they stay ours.
	err = h.service.NewPacket(ctx, &stubPacketConn{h.listener.PacketWriter()}, buffer, M.Metadata{Source: source})
	if err != nil {
		buffer.Release()
		h.logger.ErrorContext(ctx, E.Cause(err, "process packet from ", source))
	}
}
