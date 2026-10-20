package wireguard

import (
	"context"
	"github.com/sagernet/sing-tun"
)

func (w *Endpoint) WaitDetached(ctx context.Context) error {
	if w.runtime!=nil{w.runtime.mu.Lock();p:=w.runtime.physical;w.runtime.mu.Unlock();if p==nil{return nil};select{case <-p.done:return p.err;case <-ctx.Done():return ctx.Err()}}
 if w.endpoint == nil { return nil }
	return w.endpoint.WaitDetached(ctx)
}

var _ tun.StackWithDetachWaiter = (*Endpoint)(nil)
