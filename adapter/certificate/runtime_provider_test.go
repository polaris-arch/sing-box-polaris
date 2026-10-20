package certificate

import (
	"context"
	"crypto/tls"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/internal/runtimegraph"
)

type boundCertificateFixture struct {
	source adapter.RuntimeResourceSource
	fence  *outbound.RuntimeIOFence
	calls  atomic.Int32
}

func (p *boundCertificateFixture) RuntimeResourceID() adapter.RuntimeResourceID { return p.source.ID() }
func (*boundCertificateFixture) RuntimeValidate() error                         { return nil }
func (p *boundCertificateFixture) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.GetCertificateWithContext(HelloContext(hello), hello)
}

func (p *boundCertificateFixture) GetCertificateWithContext(ctx context.Context, _ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	_, release, err := BeginRuntimeCallback(ctx, p.source, p.fence)
	if err != nil {
		return nil, err
	}
	defer release()
	p.calls.Add(1)
	return &tls.Certificate{}, nil
}

func certificateOwner(t *testing.T, sequence uint64, deps []adapter.RuntimeResourceLease, closeFn func() error) *runtimegraph.ResourceOwner {
	t.Helper()
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "certificate-fixture", Sequence: sequence}, deps, closeFn)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func waitCertificateOwner(t *testing.T, owner *runtimegraph.ResourceOwner) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeCertificateReferenceRetainsExactRetiredDependency(t *testing.T) {
	provider := &boundCertificateFixture{fence: outbound.NewRuntimeIOFence(nil)}
	leaf := certificateOwner(t, 1, nil, provider.fence.RuntimeCloseAndWait)
	provider.source = leaf
	dependency, err := leaf.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	consumer := certificateOwner(t, 2, []adapter.RuntimeResourceLease{dependency}, nil)
	dependency.Release()
	ctx := adapter.ContextWithRuntimeResourceSource(context.Background(), consumer)
	reference, err := BindRuntimeProvider(ctx, provider)
	if err != nil {
		t.Fatal(err)
	}
	request, err := consumer.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	leaf.Seal()
	consumer.Seal()
	if _, err := reference.GetCertificateWithContext(adapter.ContextWithRuntimeResourceLease(ctx, request), nil); err != nil {
		t.Fatal("old exact graph continuation rejected", err)
	}
	request.Release()
	waitCertificateOwner(t, consumer)
	waitCertificateOwner(t, leaf)
	if _, err := reference.GetCertificate(nil); err == nil {
		t.Fatal("terminal reference reopened root admission")
	}
	if provider.calls.Load() != 1 {
		t.Fatal("retired reference invoked provider unexpectedly")
	}
}

func TestRuntimeCertificateReferenceRejectsMissingEdgeEvenWhenProviderOpen(t *testing.T) {
	provider := &boundCertificateFixture{fence: outbound.NewRuntimeIOFence(nil)}
	leaf := certificateOwner(t, 3, nil, provider.fence.RuntimeCloseAndWait)
	provider.source = leaf
	consumer := certificateOwner(t, 4, nil, nil)
	reference, err := BindRuntimeProvider(adapter.ContextWithRuntimeResourceSource(context.Background(), consumer), provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reference.GetCertificate(nil); err == nil {
		t.Fatal("missing graph dependency fell back to provider root")
	}
	if provider.calls.Load() != 0 {
		t.Fatal("provider reached before exact edge was retained")
	}
	consumer.Seal()
	leaf.Seal()
	waitCertificateOwner(t, consumer)
	waitCertificateOwner(t, leaf)
}

func TestRuntimeInlineCertificateReferenceCanShareExactOwner(t *testing.T) {
	provider := &boundCertificateFixture{fence: outbound.NewRuntimeIOFence(nil)}
	owner := certificateOwner(t, 5, nil, provider.fence.RuntimeCloseAndWait)
	provider.source = owner
	reference, err := BindRuntimeProvider(adapter.ContextWithRuntimeResourceSource(context.Background(), owner), provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reference.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	owner.Seal()
	waitCertificateOwner(t, owner)
}
