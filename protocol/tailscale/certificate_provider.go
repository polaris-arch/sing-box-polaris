//go:build with_tailscale

package tailscale

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/tailscale/client/local"
)

func RegisterCertificateProvider(registry *certificate.Registry) {
	certificate.Register[option.TailscaleCertificateProviderOptions](registry, C.TypeTailscale, NewCertificateProvider)
}

var _ adapter.CertificateProviderService = (*CertificateProvider)(nil)

type CertificateProvider struct {
	certificate.Adapter
	endpointTag string
	endpoint    *Endpoint
	dialer      N.Dialer
	localClient atomic.Pointer[local.Client]
}

func NewCertificateProvider(ctx context.Context, _ log.ContextLogger, tag string, options option.TailscaleCertificateProviderOptions) (adapter.CertificateProviderService, error) {
	if options.Endpoint == "" {
		return nil, E.New("missing tailscale endpoint tag")
	}
	endpointManager := service.FromContext[adapter.EndpointManager](ctx)
	rawEndpoint, loaded := endpointManager.Get(options.Endpoint)
	if !loaded {
		return nil, E.New("endpoint not found: ", options.Endpoint)
	}
	endpoint, isTailscale := rawEndpoint.(*Endpoint)
	if !isTailscale {
		return nil, E.New("endpoint is not Tailscale: ", options.Endpoint)
	}
	providerDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        option.DialerOptions{},
		RemoteIsDomain: true,
	})
	if err != nil {
		return nil, E.Cause(err, "create tailscale certificate provider dialer")
	}
	return &CertificateProvider{
		Adapter:     certificate.NewAdapter(C.TypeTailscale, tag),
		endpointTag: options.Endpoint,
		endpoint:    endpoint,
		dialer:      providerDialer,
	}, nil
}

func (p *CertificateProvider) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	localClient, err := p.endpoint.NewLocalClient()
	if err != nil {
		return E.Cause(err, "initialize tailscale local client for endpoint ", p.endpointTag)
	}
	originalDial := localClient.Dial
	localClient.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if originalDial != nil && addr == "local-tailscaled.sock:80" {
			return originalDial(ctx, network, addr)
		}
		return p.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
	}
	p.localClient.Store(localClient)
	return nil
}

func (p *CertificateProvider) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	localClient := p.localClient.Load()
	if localClient == nil {
		return nil, E.New("Tailscale is not ready yet")
	}
	var certificate *tls.Certificate
	err := p.endpoint.WithDirectoryAccess(func() error {
		var err error
		certificate, err = localClient.GetCertificate(clientHello)
		return err
	})
	return certificate, err
}
