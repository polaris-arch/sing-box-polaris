package box

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	originca "github.com/sagernet/sing-box/service/origin_ca"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type runtimeCertificateAliasEffect struct{ stage func() error }

func (*runtimeCertificateAliasEffect) RuntimeConflictKeys() []string {
	return []string{"fixture:certificate-alias"}
}
func (e *runtimeCertificateAliasEffect) StageRuntime(context.Context) error { return e.stage() }
func (*runtimeCertificateAliasEffect) SuspendRuntime(context.Context) error { return nil }
func (*runtimeCertificateAliasEffect) RestoreRuntime(context.Context) error { return nil }
func (*runtimeCertificateAliasEffect) RuntimeExternalEffects() bool         { return true }
func (*runtimeCertificateAliasEffect) RuntimeActivate()                     {}
func (*runtimeCertificateAliasEffect) RuntimeStop()                         {}

type runtimeCertificatePartialProvider struct {
	*originca.Service
	before    func() error
	uncertain bool
}

func (p *runtimeCertificatePartialProvider) StageRuntime(ctx context.Context) error {
	if p.before != nil {
		if err := p.before(); err != nil {
			return err
		}
	}
	return p.Service.StageRuntime(ctx)
}

func (p *runtimeCertificatePartialProvider) CompensateRuntime() error {
	err := p.Service.CompensateRuntime()
	if p.uncertain {
		err = errors.Join(err, errors.New("fixture partial cache cleanup remains unknown"))
	}
	return err
}

func runtimeCertificateAliasPaths(t *testing.T) (string, string, string, func() error) {
	t.Helper()
	root := t.TempDir()
	a, b, l := filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "alias")
	for _, dir := range []string{a, b} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(a, l); err != nil {
		t.Skip("private symlink fixture unavailable")
	}
	return a, b, l, func() error {
		if err := os.Remove(l); err != nil {
			return err
		}
		return os.Symlink(b, l)
	}
}

func TestRuntimeCertificatePublicationRechecksAliasAfterActualOriginCAStage(t *testing.T) {
	a, b, l, flip := runtimeCertificateAliasPaths(t)
	key, ca, server := runtimeCertificateTestSigner(t)
	var issued atomic.Int64
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "publication-alias.test"), func(o *runtimeTestSocks) error {
		o.dialHook = func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			return runtimeCertificateTestPipe(t, key, ca, server, issued.Add(1)+1), nil
		}
		return nil
	})
	registry := service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry)
	certificate.Register[option.CloudflareOriginCACertificateProviderOptions](registry, "cloudflare-origin-ca", func(ctx context.Context, logger log.ContextLogger, tag string, value option.CloudflareOriginCACertificateProviderOptions) (adapter.CertificateProviderService, error) {
		provider, err := originca.NewCertificateProvider(ctx, logger, tag, value)
		if err != nil {
			return nil, err
		}
		if err = adapter.RegisterRuntimePostBindEffect(ctx, &runtimeCertificateAliasEffect{stage: flip}); err != nil {
			return nil, err
		}
		return provider, nil
	})
	runtimeResourceNew(t, f, options)
	f.start(t)
	before := f.identity()
	options.HTTPClients = []option.HTTPClient{{Tag: "issuer", Version: 1, Detour: "a", TLS: &option.OutboundTLSOptions{Insecure: true}}}
	options.CertificateProviders = []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: &option.CloudflareOriginCACertificateProviderOptions{Domain: []string{"race.invalid"}, DataDirectory: l, APIToken: "fixture", RequestType: option.CloudflareOriginCARequestTypeOriginECC, HTTPClient: &option.HTTPClientOptions{Tag: "issuer"}}}}
	_, apply := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	operation := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
	if operation.Active != before || f.identity() != before || issued.Load() != 1 {
		t.Fatal("post-bind alias drift was published or did not exercise actual first issuance", operation, issued.Load())
	}
	files, err := os.ReadDir(a)
	if err != nil || len(files) == 0 {
		t.Fatal("real OriginCA stage did not touch reserved directory", err)
	}
	files, err = os.ReadDir(b)
	if err != nil || len(files) != 0 {
		t.Fatal("staged storage followed changed alias into unowned directory", err)
	}
}

func TestRuntimeCertificatePartialStageUnknownCleanupRetainsHistoryFreshAndBoundInPublicPlan(t *testing.T) {
	a, b, l, flip := runtimeCertificateAliasPaths(t)
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "unknown-alias.test"), nil)
	var constructed atomic.Int32
	registry := service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry)
	certificate.Register[option.CloudflareOriginCACertificateProviderOptions](registry, "cloudflare-origin-ca", func(ctx context.Context, logger log.ContextLogger, tag string, value option.CloudflareOriginCACertificateProviderOptions) (adapter.CertificateProviderService, error) {
		constructed.Add(1)
		raw, err := originca.NewCertificateProvider(ctx, logger, tag, value)
		if err != nil {
			return nil, err
		}
		p := &runtimeCertificatePartialProvider{Service: raw.(*originca.Service), uncertain: true}
		p.before = func() error {
			if err := flip(); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(b, "partial-effect"), []byte("fixture partial cache side effect"), 0o600)
		}
		if err = adapter.DeferConstructionCleanup(ctx, func() error { return errors.New("fixture cleanup completion unknown") }); err != nil {
			return nil, err
		}
		return p, nil
	})
	// This intentional cleanup-uncertainty fixture checks the retained catalog;
	// the actual Root/worker is still stopped by the real OriginCA cleanup.
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	f.start(t)
	before := f.identity()
	provider := &option.CloudflareOriginCACertificateProviderOptions{Domain: []string{"partial.invalid"}, DataDirectory: l, APIToken: "fixture", RequestType: option.CloudflareOriginCARequestTypeOriginECC}
	options.CertificateProviders = []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "partial", Options: provider}}
	_, apply := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	operation := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
	if operation.Active != before || f.identity() != before {
		t.Fatal("partial stage changed graph", operation)
	}
	effects, compensation := false, false
	for _, problem := range operation.Errors {
		effects = effects || problem.Code == "EXTERNAL_EFFECTS_MAY_REMAIN"
		compensation = compensation || problem.Code == "CERTIFICATE_COMPENSATION_INCOMPLETE"
	}
	if !effects || !compensation {
		t.Fatal("partial issuance lost external/uncertain compensation evidence", operation.Errors)
	}

	var resource *runtimeResource
	instance.runtime.access.Lock()
	for _, candidate := range instance.runtime.catalog {
		for _, claim := range candidate.certificateClaims {
			if claim.component == "certificate-provider:partial" {
				resource = candidate
			}
		}
	}
	instance.runtime.access.Unlock()
	if resource == nil {
		t.Fatal("failed allocation lost its charged storage claims")
	}
	if err = resource.owner.WaitClosed(runtimeTestContext(t)); err == nil {
		t.Fatal("fixture did not reach UnknownCleanup")
	}
	infoA, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	infoB, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	var heldA, heldB bool
	instance.runtime.access.Lock()
	instance.runtime.pruneRuntimeCatalogLocked()
	for _, claim := range resource.certificateClaims {
		heldA = heldA || (claim.object != nil && os.SameFile(claim.object, infoA))
		heldB = heldB || (claim.object != nil && os.SameFile(claim.object, infoB))
	}
	retained := instance.runtime.catalog[resource.id] != nil
	instance.runtime.access.Unlock()
	if !heldA || !heldB || !retained {
		t.Fatal("UnknownCleanup lost historical A or fresh/bound B ownership", heldA, heldB, retained)
	}
	provider.DataDirectory = b
	options.CertificateProviders[0].Tag = "next"
	plan, err := instance.planRuntimeConfig(context.Background(), "actor-a", before, runtimeResourceEncode(t, f, options.Options))
	if err != nil || plan.Applicable || len(plan.Errors) == 0 || plan.Errors[0].Code != "RESTART_REQUIRED" || constructed.Load() != 1 {
		t.Fatal("public Plan ignored B touched by unknown-cleanup owner", plan, err, constructed.Load())
	}
}

func TestRuntimeRetainedOriginCAAliasMayMoveWithoutTransferringItsStorageToNextProvider(t *testing.T) {
	_, b, l, flip := runtimeCertificateAliasPaths(t)
	key, ca, server := runtimeCertificateTestSigner(t)
	var issued atomic.Int64
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "retained-alias.test"), func(o *runtimeTestSocks) error {
		o.dialHook = func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			return runtimeCertificateTestPipe(t, key, ca, server, issued.Add(1)+1), nil
		}
		return nil
	})
	originca.RegisterCertificateProvider(service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry))
	options.HTTPClients = []option.HTTPClient{{Tag: "issuer", Version: 1, Detour: "a", TLS: &option.OutboundTLSOptions{Insecure: true}}}
	provider := &option.CloudflareOriginCACertificateProviderOptions{Domain: []string{"retained.invalid"}, DataDirectory: l, APIToken: "fixture", RequestType: option.CloudflareOriginCARequestTypeOriginECC, HTTPClient: &option.HTTPClientOptions{Tag: "issuer"}}
	options.CertificateProviders = []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "old", Options: provider}}
	runtimeResourceNew(t, f, options)
	f.start(t)
	oldLease, oldView := f.acquire(t)
	oldResource := runtimeTestResource(t, f, oldView.componentIDs["certificate-provider:old"])
	oldProvider := oldResource.components["certificate-provider:old"].provider.(certificate.RuntimeProvider)
	if err := flip(); err != nil {
		t.Fatal(err)
	}
	provider.DataDirectory = b
	provider.Domain = []string{"next.invalid"}
	options.CertificateProviders[0].Tag = "next"
	_, apply := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	operation := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
	if operation.Active.Revision != apply.Expected.Revision+1 || issued.Load() != 2 {
		t.Fatal("disjoint pinned root could not coexist with new physical directory", operation, issued.Load())
	}
	leaf, err := oldProvider.GetCertificateWithContext(adapter.ContextWithRuntimeLease(runtimeTestContext(t), oldLease), nil)
	if err != nil || leaf == nil {
		t.Fatal("retained provider lost exact epoch callback", err)
	}
	if err = leaf.Leaf.VerifyHostname("retained.invalid"); err != nil {
		t.Fatal("retained provider consulted replacement", err)
	}
	select {
	case <-oldResource.owner.Closed():
		t.Fatal("retained old provider root closed before old epoch drained")
	default:
	}
	oldLease.Release()
	runtimeTestWait(t, oldResource.owner.Closed(), "old provider root cleanup after last exact lease")
}
