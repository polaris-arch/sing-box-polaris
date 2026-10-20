//go:build with_tailscale

package tailscale

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/httpclient"
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
	runtime *runtimeCertificateProvider
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
	result := &CertificateProvider{
		Adapter:     certificate.NewAdapter(C.TypeTailscale, tag),
		endpointTag: options.Endpoint,
		endpoint:    endpoint,
		dialer:      providerDialer,
	}
	if adapter.IsRuntimePreparation(ctx) {
		if err := result.initializeRuntime(ctx); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (p *CertificateProvider) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if p.runtime != nil {
		return p.PrepareRuntime(stage, scope)
	}
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
	if p.runtime != nil {
		return p.GetCertificateWithContext(certificate.HelloContext(clientHello), clientHello)
	}
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

// The endpoint owns tailscaled, its filesystem scope, dialers and callbacks.
// A certificate provider cannot certify that lifecycle on the endpoint's behalf.
// Box must include this exact allocation in the provider dependency closure and
// finish endpoint staging before StageRuntime obtains the private LocalClient.
type runtimeCertificateEndpoint interface {
	RuntimeResourceID() adapter.RuntimeResourceID
	RuntimeValidate() error
}

type runtimeCertificateProvider struct {
	ctx           context.Context
	cancel        context.CancelFunc
	source        adapter.RuntimeResourceSource
	endpointID    adapter.RuntimeResourceID
	fence         *outbound.RuntimeIOFence
	beginOwned    func(context.Context) (context.Context, func(), error)
	transport     *http.Transport
	boundary      *httpclient.RuntimeTransportBoundary
	mu            sync.Mutex
	prepared      bool
	stopped       bool
	active        bool
	stageDone     chan struct{}
	stageErr      error
	stageReturned bool
}

var (
	_ certificate.RuntimePreparedProvider = (*CertificateProvider)(nil)
	_ certificate.RuntimeProvider         = (*CertificateProvider)(nil)
)

func validateRuntimeCertificateEndpoint(value any, tag string) (adapter.RuntimeResourceID, error) {
	endpoint, ok := value.(runtimeCertificateEndpoint)
	if !ok {
		return adapter.RuntimeResourceID{}, E.New("Tailscale endpoint ", tag, " requires its staged runtime resource adapter before certificate-provider HOT")
	}
	if err := endpoint.RuntimeValidate(); err != nil {
		return adapter.RuntimeResourceID{}, err
	}
	id := endpoint.RuntimeResourceID()
	if id == (adapter.RuntimeResourceID{}) {
		return id, errors.New("tailscale endpoint has no runtime resource identity")
	}
	return id, nil
}

func (p *CertificateProvider) initializeRuntime(ctx context.Context) error {
	endpointID, err := validateRuntimeCertificateEndpoint(p.endpoint, p.endpointTag)
	if err != nil {
		return err
	}
	source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
	if !ok || !adapter.HasConstructionScope(ctx) {
		return errors.New("tailscale certificate provider requires its constructor resource and scope")
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &runtimeCertificateProvider{ctx: ctx, cancel: cancel, source: source, endpointID: endpointID}
	p.runtime = r
	r.transport = &http.Transport{}
	r.boundary = httpclient.NewRuntimeTransportBoundary(func() error { r.transport.CloseIdleConnections(); return nil })
	r.fence = outbound.NewRuntimeIOFence(func() error {
		p.RuntimeStop()
		// Transport close cancels current requests and detached physical dials, and
		// seals/join their socket and graph callback boundaries before owner release.
		closeErr := r.boundary.RuntimeCloseAndWait()
		r.mu.Lock()
		stage := r.stageDone
		r.mu.Unlock()
		if stage != nil {
			<-stage
		}
		r.mu.Lock()
		incomplete := r.stageDone != nil && !r.stageReturned
		r.mu.Unlock()
		if incomplete {
			closeErr = errors.Join(closeErr, errors.New("tailscale certificate stage completion unknown"))
		}
		if closeErr != nil {
			return fmt.Errorf("tailscale certificate cleanup incomplete: %v", closeErr)
		}
		return nil
	})
	begin, err := outbound.RegisterRuntimeOwnedFence(ctx, r.fence)
	if err != nil {
		cancel()
		return err
	}
	r.beginOwned = begin
	return nil
}

func (p *CertificateProvider) RuntimeResourceID() adapter.RuntimeResourceID {
	if p.runtime == nil {
		return adapter.RuntimeResourceID{}
	}
	return p.runtime.source.ID()
}

func (p *CertificateProvider) RuntimeDependencies() []adapter.RuntimeResourceID {
	if p.runtime == nil {
		return nil
	}
	return []adapter.RuntimeResourceID{p.runtime.endpointID}
}

func (p *CertificateProvider) RuntimeValidate() error {
	if p.runtime == nil {
		return errors.New("tailscale certificate provider lacks a staged endpoint and provider owner")
	}
	return nil
}

func (p *CertificateProvider) PrepareRuntime(stage adapter.StartStage, _ *adapter.Scope) error {
	if err := p.RuntimeValidate(); err != nil {
		return err
	}
	r := p.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return net.ErrClosed
	}
	if stage == adapter.StartStateStarted {
		r.prepared = true
	}
	return r.ctx.Err()
}

func (p *CertificateProvider) StageRuntime(ctx context.Context) error {
	r := p.runtime
	leave, err := r.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	r.mu.Lock()
	if !r.prepared || r.stopped {
		r.mu.Unlock()
		return errors.New("tailscale certificate provider not prepared for staging")
	}
	if r.stageDone != nil {
		done := r.stageDone
		r.mu.Unlock()
		<-done
		r.mu.Lock()
		err := r.stageErr
		r.mu.Unlock()
		return err
	}
	r.stageDone = make(chan struct{})
	done := r.stageDone
	r.stageErr = errors.New("tailscale certificate stage did not complete")
	r.mu.Unlock()
	defer close(done)
	err = p.stageLocalClient(ctx)
	r.mu.Lock()
	r.stageErr, r.stageReturned = err, true
	r.mu.Unlock()
	return err
}

func (p *CertificateProvider) stageLocalClient(ctx context.Context) error {
	r := p.runtime
	ctx, leave, err := r.beginOwned(ctx)
	if err != nil {
		return err
	}
	defer leave()
	ctx, releaseEndpoint, err := certificate.RetainRuntimeDependency(ctx, r.source.ID(), r.endpointID)
	if err != nil {
		return err
	}
	defer releaseEndpoint()
	if err := ctx.Err(); err != nil {
		return err
	}
	client, err := p.endpoint.NewLocalClient()
	if err != nil {
		return err
	}
	originalDial := client.Dial
	r.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return r.boundary.Dial(ctx, func(ctx context.Context) (net.Conn, error) {
			owned, release, err := r.beginOwned(ctx)
			if err != nil {
				return nil, err
			}
			defer release()
			owned, releaseEndpoint, err := certificate.RetainRuntimeDependency(owned, r.source.ID(), r.endpointID)
			if err != nil {
				return nil, err
			}
			defer releaseEndpoint()
			owned, err = outbound.ContextForRuntimeOwnedSession(owned, r.source)
			if err != nil {
				return nil, err
			}
			if originalDial != nil && address == "local-tailscaled.sock:80" {
				return originalDial(owned, network, address)
			}
			return p.dialer.DialContext(owned, network, M.ParseSocksaddr(address))
		})
	}
	client.Transport = &runtimeCertificateRoundTripper{runtime: r}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.localClient.Store(client)
	return nil
}

type runtimeCertificateRoundTripper struct{ runtime *runtimeCertificateProvider }

func (t *runtimeCertificateRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.runtime.boundary.RoundTrip(request, t.runtime.transport.RoundTrip)
}

func (p *CertificateProvider) RuntimeActivate() {
	r := p.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopped && r.stageReturned && r.stageErr == nil {
		r.active = true
	}
}

func (p *CertificateProvider) RuntimeStop() {
	r := p.runtime
	r.mu.Lock()
	r.stopped = true
	r.mu.Unlock()
	r.cancel()
}

func (p *CertificateProvider) RuntimeCloseAndWait() error {
	if p.runtime == nil {
		return nil
	}
	return p.runtime.fence.RuntimeCloseAndWait()
}
func (p *CertificateProvider) CompensateRuntime() error { return p.RuntimeCloseAndWait() }
func (p *CertificateProvider) GetCertificateWithContext(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p.runtime == nil {
		return p.GetCertificate(hello)
	}
	r := p.runtime
	ctx, release, err := certificate.BeginRuntimeCallback(ctx, r.source, r.fence)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx, releaseEndpoint, err := certificate.RetainRuntimeDependency(ctx, r.source.ID(), r.endpointID)
	if err != nil {
		return nil, err
	}
	defer releaseEndpoint()
	r.mu.Lock()
	active := r.active
	r.mu.Unlock()
	if !active {
		return nil, errors.New("tailscale certificate provider is not active")
	}
	if hello == nil || hello.ServerName == "" {
		return nil, errors.New("no SNI ServerName")
	}
	client := p.localClient.Load()
	if client == nil {
		return nil, errors.New("tailscale certificate local client is not ready")
	}
	// Pinned local.Client.GetCertificate replaces caller context with Background.
	// Its public ExpandSNIName and CertPair APIs preserve the admitted lineage and
	// cancellation, retaining the existing one-minute certificate request bound.
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var result *tls.Certificate
	err = p.endpoint.WithDirectoryAccess(func() error {
		name := hello.ServerName
		if !strings.Contains(name, ".") {
			if expanded, ok := client.ExpandSNIName(ctx, name); ok {
				name = expanded
			}
		}
		certPEM, keyPEM, err := client.CertPair(ctx, name)
		if err != nil {
			return err
		}
		value, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return err
		}
		result = &value
		return nil
	})
	return result, err
}

func (p *CertificateProvider) RuntimeExternalEffects() bool { return true }
