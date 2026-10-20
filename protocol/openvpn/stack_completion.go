package openvpn

import (
	"context"
	"github.com/sagernet/sing-tun"
)

// WaitDetached requires prior lifecycle Close. It observes the actual stack
// completion, not native protocol replacement eligibility.
func (c *ClientEndpoint) WaitDetached(ctx context.Context) error {
	if c.device == nil { return nil }
	return c.device.WaitDetached(ctx)
}

var _ tun.StackWithDetachWaiter = (*ClientEndpoint)(nil)

// WaitDetached requires prior lifecycle Close. It observes the actual stack
// completion, not native protocol replacement eligibility.
func (s *ServerEndpoint) WaitDetached(ctx context.Context) error {
	if s.device == nil { return nil }
	return s.device.WaitDetached(ctx)
}

var _ tun.StackWithDetachWaiter = (*ServerEndpoint)(nil)

