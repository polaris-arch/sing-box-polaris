package naive

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/transport/runtimeingress"
	N "github.com/sagernet/sing/common/network"
)

func (r *inboundRuntime) EnterRuntimeIngress(ctx context.Context) (context.Context, func(), error) {
	return r.enter(ctx)
}

func (r *inboundRuntime) wrapConnection(ctx context.Context, conn net.Conn, onClose N.CloseHandlerFunc) (net.Conn, N.CloseHandlerFunc, error) {
	return runtimeingress.WrapConnection(ctx, conn, onClose, r)
}
