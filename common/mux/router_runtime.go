package mux

import (
 "context"
 "errors"
 "net"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/outbound"
 "github.com/sagernet/sing/common/logger"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)

type runtimeServerHandler struct {
 handler adapter.UpstreamHandlerAdapter
 callbacks *outbound.RuntimeIOFence
}
func newRuntimeServerHandler(ctx context.Context, handler adapter.UpstreamHandlerAdapter, logger logger.ContextLogger) (adapter.UpstreamHandlerAdapter, logger.ContextLogger, error) {
 if !adapter.IsRuntimePreparation(ctx) { return handler, logger, nil }
 if !adapter.HasConstructionScope(ctx) { return nil, nil, errors.New("runtime multiplex server requires construction cleanup") }
 callbacks := outbound.NewRuntimeIOFence(nil)
 if err := adapter.DeferConstructionCleanup(ctx, callbacks.RuntimeCloseAndWait); err != nil { return nil, nil, err }
 if err := adapter.ConstructionScopeErr(ctx); err != nil { return nil, nil, err }
 return &runtimeServerHandler{handler:handler, callbacks:callbacks}, outbound.WrapRuntimeLogger(logger, callbacks), nil
}
func (h *runtimeServerHandler) enter(ctx context.Context) (context.Context, func(), error) {
 leave, err := h.callbacks.Acquire()
 if err != nil { return nil, nil, err }
 owned, release, err := adapter.AcquireRuntimeOperation(ctx, nil)
 if err != nil { leave(); return nil, nil, err }
 if _, ok := adapter.RuntimeLeaseFromContext(owned); !ok { release(); leave(); return nil, nil, errors.New("multiplex stream has no physical ingress lineage") }
 return owned, func(){release(); leave()}, nil
}
func (h *runtimeServerHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
 ctx, release, err := h.enter(ctx)
 if err != nil { N.CloseOnHandshakeFailure(conn, onClose, err); return }; defer release()
 h.handler.NewConnectionEx(ctx, conn, source, destination, onClose)
}
func (h *runtimeServerHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
 ctx, release, err := h.enter(ctx)
 if err != nil { N.CloseOnHandshakeFailure(conn, onClose, err); return }; defer release()
 h.handler.NewPacketConnectionEx(ctx, conn, source, destination, onClose)
}
