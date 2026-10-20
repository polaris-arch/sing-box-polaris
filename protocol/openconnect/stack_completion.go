package openconnect

import (
	"context"

	"github.com/sagernet/sing-tun"
)

// WaitDetached requires prior lifecycle Close. It observes the actual stack
// completion, not native protocol replacement eligibility.
func (e *Endpoint) WaitDetached(ctx context.Context) error {
	if e.device == nil {
		return nil
	}
	return e.device.WaitDetached(ctx)
}

var _ tun.StackWithDetachWaiter = (*Endpoint)(nil)
