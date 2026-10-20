// Package runtimeingress preserves the admitted physical connection's lineage
// through protocol server wrappers. It never acquires the current graph.
package runtimeingress

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
)

type Conn struct {
	net.Conn
	Context context.Context
}

func (c *Conn) RuntimeIngressContext() context.Context { return c.Context }

// Context follows only the concrete TLS NetConn contract and our private
// lineage marker. No raw socket is returned to callers. A missing marker leaves
// legacy context unchanged; staged handlers independently reject absent leases.
func Context(fallback context.Context, conn net.Conn) context.Context {
	for depth := 0; conn != nil && depth < 16; depth++ {
		if owned, ok := conn.(interface{ RuntimeIngressContext() context.Context }); ok {
			return owned.RuntimeIngressContext()
		}
		tls, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			return fallback
		}
		next := tls.NetConn()
		if next == conn {
			return fallback
		}
		conn = next
	}
	return fallback
}

func Acquire(ctx context.Context, staged bool) (context.Context, func(), error) {
	if !staged {
		return ctx, func() {}, nil
	}
	// An incoming physical carrier must supply lineage. Resource-only or current
	// admission fallback would silently move an old HTTP/2 stream to a new graph.
	if _, ok := adapter.RuntimeLeaseFromContext(ctx); !ok {
		return nil, nil, net.ErrClosed
	}
	return adapter.AcquireRuntimeOperation(ctx, nil)
}
