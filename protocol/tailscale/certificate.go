//go:build with_tailscale

package tailscale

import (
	"context"
	"time"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

func (t *Endpoint) GetTailscaleCertificate(ctx context.Context, domain string, minValidity time.Duration) ([]byte, []byte, error) {
	if t.runtime != nil {
		child, ctx, leave, err := t.runtimeOperation(ctx)
		if err != nil {
			return nil, nil, err
		}
		defer leave()
		return child.GetTailscaleCertificate(ctx, domain, minValidity)
	}

	if !t.started.Load() {
		return nil, nil, E.New("Tailscale is not ready yet")
	}
	var certificatePEM, privateKeyPEM []byte
	var err error
	if t.runtimePhysical != nil {
		certificatePEM, privateKeyPEM, err = t.server.RuntimeCertificatePair(ctx, domain, minValidity)
	} else {
		certificatePEM, privateKeyPEM, err = common.Must1(t.server.LocalClient()).CertPairWithValidity(ctx, domain, minValidity)
	}
	if err != nil {
		return nil, nil, E.Cause(err, "tailscale certificate")
	}
	return certificatePEM, privateKeyPEM, nil
}
