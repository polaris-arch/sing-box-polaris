package shadowtls

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type (
	runtimeHandshakeKey      struct{}
	runtimeHandshakeCarriers struct {
		access sync.Mutex
		conns  []net.Conn
	}
)

func (c *runtimeHandshakeCarriers) close() error {
	c.access.Lock()
	conns := c.conns
	c.conns = nil
	c.access.Unlock()
	var err error
	for _, conn := range conns {
		err = errors.Join(err, conn.Close())
	}
	return err
}

type runtimeHandshakeDialer struct{ N.Dialer }

func (d *runtimeHandshakeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	carriers, ok := ctx.Value(runtimeHandshakeKey{}).(*runtimeHandshakeCarriers)
	if !ok {
		return nil, errors.New("ShadowTLS runtime handshake has no admitted carrier owner")
	}
	// This is an external physical connection belonging to the incoming handshake,
	// not an idle library pool. Keep its exact graph and all receiving resources.
	conn, err := outbound.DialRuntimeConn(ctx, nil, func(owned context.Context) (net.Conn, error) {
		return d.Dialer.DialContext(owned, network, destination)
	})
	if err != nil {
		return nil, err
	}
	carriers.access.Lock()
	carriers.conns = append(carriers.conns, conn)
	carriers.access.Unlock()
	return conn, nil
}

func runtimeHandshakeFor(r *inboundRuntime, dialer N.Dialer) N.Dialer {
	if r == nil {
		return dialer
	}
	return &runtimeHandshakeDialer{Dialer: dialer}
}
