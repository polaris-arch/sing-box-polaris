//go:build !darwin

package local

import (
	"context"
	"os"

	mDNS "github.com/miekg/dns"
)

type systemResolver struct{}

func (r *systemResolver) stop() {}

func (r *systemResolver) close() error { return nil }

func (r *systemResolver) reset() {}

func (*systemResolver) setKeepIdleConnections(bool) {}

func (*systemResolver) closeIdleConnections() {}

func (t *Transport) systemExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	callback(nil, os.ErrInvalid)
}
