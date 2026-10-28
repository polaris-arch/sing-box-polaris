package certificate

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
)

// RuntimeProvider identifies an allocation, never a mutable manager/tag lookup.
// Implementations must reserve their actual source and callback fence before
// accessing provider state. The context variant preserves the TLS consumer's
// immutable graph lineage even for libraries whose ClientHello cannot be cloned.
type RuntimeProvider interface {
	adapter.CertificateProvider
	RuntimeValidate() error
	RuntimeResourceID() adapter.RuntimeResourceID
	GetCertificateWithContext(context.Context, *tls.ClientHelloInfo) (*tls.Certificate, error)
}

func HelloContext(hello *tls.ClientHelloInfo) context.Context {
	if hello != nil {
		if ctx := hello.Context(); ctx != nil {
			return ctx
		}
	}
	return context.Background()
}

func BeginRuntimeCallback(ctx context.Context, source adapter.RuntimeResourceSource, fence *outbound.RuntimeIOFence) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, source)
	if err != nil {
		return nil, nil, err
	}
	leave, err := fence.Acquire()
	if err != nil {
		release()
		return nil, nil, err
	}
	return owned, func() { leave(); release() }, nil
}

// RuntimeReference captures both exact allocations. Box must put the provider
// ID in the consumer's constructor dependency closure before publication.
// This is a borrowed reference; it never owns provider Start or Close.
type RuntimeReference struct {
	provider RuntimeProvider
	source   adapter.RuntimeResourceSource
	id       adapter.RuntimeResourceID
}

func BindRuntimeProvider(ctx context.Context, provider adapter.CertificateProvider) (*RuntimeReference, error) {
	runtime, ok := provider.(RuntimeProvider)
	if !ok {
		return nil, errors.New("certificate provider lacks context-bound runtime callbacks")
	}
	if err := runtime.RuntimeValidate(); err != nil {
		return nil, err
	}
	source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
	if !ok {
		return nil, errors.New("TLS certificate consumer has no runtime resource source")
	}
	id := runtime.RuntimeResourceID()
	if id == (adapter.RuntimeResourceID{}) {
		return nil, errors.New("certificate provider has no runtime resource identity")
	}
	return &RuntimeReference{provider: runtime, source: source, id: id}, nil
}
func (p *RuntimeReference) RuntimeResourceID() adapter.RuntimeResourceID { return p.id }
func (p *RuntimeReference) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.GetCertificateWithContext(HelloContext(hello), hello)
}

func (p *RuntimeReference) GetCertificateWithContext(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, p.source)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx, releaseDependency, err := RetainRuntimeDependency(ctx, p.source.ID(), p.id)
	if err != nil {
		return nil, err
	}
	defer releaseDependency()
	return p.provider.GetCertificateWithContext(ctx, hello)
}

// RetainRuntimeDependency accepts only the receiving owner's captured closure;
// it cannot fall back to another current graph or to tag-based root admission.
func RetainRuntimeDependency(ctx context.Context, owner, target adapter.RuntimeResourceID) (context.Context, func(), error) {
	receiver, ok := adapter.RuntimeResourceLeaseFromContext(ctx, owner)
	if !ok {
		return nil, nil, errors.New("certificate receiver was not retained")
	}
	closure, ok := receiver.(adapter.RuntimeResourceContinuation)
	if !ok {
		return nil, nil, errors.New("certificate receiver lacks immutable dependency closure")
	}
	dependency, err := closure.RetainResource(target)
	if err != nil {
		return nil, nil, err
	}
	return adapter.ContextWithRuntimeResourceLease(ctx, dependency), dependency.Release, nil
}

func (p *RuntimeReference) GetACMENextProtos() []string {
	if provider, ok := p.provider.(adapter.ACMECertificateProvider); ok {
		return append([]string(nil), provider.GetACMENextProtos()...)
	}
	return nil
}
