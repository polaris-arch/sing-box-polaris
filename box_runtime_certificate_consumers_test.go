package box

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	stdjson "encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	originca "github.com/sagernet/sing-box/service/origin_ca"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// The listener is replaced by an inert inventory member. The TLS constructor,
// provider registry, staged Origin CA issuer, managed HTTP and graph closure are
// the real production path; the CA is an in-memory test signer over net.Pipe.
type runtimeCertificateTLSConsumer struct {
	tag    string
	config boxtls.ServerConfig
}

func (i *runtimeCertificateTLSConsumer) Type() string { return "http" }
func (i *runtimeCertificateTLSConsumer) Tag() string  { return i.tag }
func (*runtimeCertificateTLSConsumer) Start(adapter.StartStage, *adapter.Scope) error {
	return errors.New("legacy Start is forbidden")
}
func (*runtimeCertificateTLSConsumer) RuntimeValidate() error { return nil }
func (i *runtimeCertificateTLSConsumer) PrepareRuntime(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		return i.config.Start()
	}
	return nil
}
func (*runtimeCertificateTLSConsumer) RuntimeListeners() []*listener.Listener { return nil }

func runtimeCertificateTestSigner(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, stdtls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"fixture.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert, stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func runtimeCertificateTestPipe(t *testing.T, key *ecdsa.PrivateKey, ca *x509.Certificate, serverCert stdtls.Certificate, serial int64) net.Conn {
	t.Helper()
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
	go func() {
		defer peer.Close()
		server := stdtls.Server(peer, &stdtls.Config{Certificates: []stdtls.Certificate{serverCert}, MinVersion: stdtls.VersionTLS12})
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		defer request.Body.Close()
		var body struct {
			CSR       string   `json:"csr"`
			Hostnames []string `json:"hostnames"`
		}
		if err = stdjson.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		block, _ := pem.Decode([]byte(body.CSR))
		if block == nil {
			t.Error("missing real issuer CSR")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Error(err)
			return
		}
		if err = csr.CheckSignature(); err != nil {
			t.Error(err)
			return
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: body.Hostnames, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
		if err != nil {
			t.Error(err)
			return
		}
		response, err := stdjson.Marshal(map[string]any{"success": true, "result": map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}})
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(response), response)
	}()
	return client
}

func runtimeCertificateHandshake(t *testing.T, lease adapter.RuntimeLease, consumer *runtimeCertificateTLSConsumer, want string) {
	t.Helper()
	config, err := consumer.config.STDConfig()
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	server := stdtls.Server(a, config)
	client := stdtls.Client(b, &stdtls.Config{InsecureSkipVerify: true, ServerName: want})
	ctx := adapter.ContextWithRuntimeLease(runtimeTestContext(t), lease)
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(ctx) }()
	if err = client.HandshakeContext(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	leaf := client.ConnectionState().PeerCertificates[0]
	if err = leaf.VerifyHostname(want); err != nil {
		t.Fatalf("TLS consulted replacement provider instead of captured allocation: %v", err)
	}
}

func TestRuntimeCertificateNamedAndInlineReplacementBindsRealTLSAndHTTP(t *testing.T) {
	for _, named := range []bool{true, false} {
		t.Run(fmt.Sprintf("named=%t", named), func(t *testing.T) {
			key, ca, serverCert := runtimeCertificateTestSigner(t)
			var issued atomic.Int64
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "issuer.test"), func(o *runtimeTestSocks) error {
				o.dialHook = func(context.Context, string, M.Socksaddr) (net.Conn, error) {
					return runtimeCertificateTestPipe(t, key, ca, serverCert, issued.Add(1)+1), nil
				}
				return nil
			})
			originca.RegisterCertificateProvider(service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry))
			registry := service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry)
			inbound.Register[option.HTTPInboundOptions](registry, "http", func(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.HTTPInboundOptions) (adapter.Inbound, error) {
				cfg, err := boxtls.NewSTDServer(ctx, logger, *options.TLS)
				if err != nil {
					return nil, err
				}
				return &runtimeCertificateTLSConsumer{tag: tag, config: cfg}, nil
			})
			provider := &option.CloudflareOriginCACertificateProviderOptions{Domain: []string{"old.invalid"}, DataDirectory: filepath.Join(t.TempDir(), "old"), APIToken: "fixture-token", RequestType: option.CloudflareOriginCARequestTypeOriginECC, HTTPClient: &option.HTTPClientOptions{Tag: "issuer"}}
			options.HTTPClients = []option.HTTPClient{{Tag: "issuer", Version: 1, TLS: &option.OutboundTLSOptions{Insecure: true}, Detour: "a"}}
			tlsOptions := &option.InboundTLSOptions{Enabled: true, CertificateProvider: &option.CertificateProviderOptions{Type: "cloudflare-origin-ca", Options: provider}}
			if named {
				options.CertificateProviders = []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: provider}}
				tlsOptions.CertificateProvider = &option.CertificateProviderOptions{Tag: "cert"}
			}
			options.Inbounds = []option.Inbound{{Type: "http", Tag: "tls", Options: &option.HTTPInboundOptions{TLS: tlsOptions}}}
			runtimeResourceNew(t, f, options)
			if issued.Load() != 0 {
				t.Fatal("constructor performed issuance")
			}
			f.start(t)
			oldLease, oldView := f.acquire(t)
			oldRaw, _ := oldView.inbounds.Get("tls")
			oldConsumer := oldRaw.(*runtimeCertificateTLSConsumer)
			runtimeCertificateHandshake(t, oldLease, oldConsumer, "old.invalid")
			// Publish an unrelated real change. An unchanged provider and its TLS
			// consumer must retain the exact allocation, rather than being rebuilt
			// merely because they are present in the candidate.
			options.Outbounds[1].Options.(*option.SOCKSOutboundOptions).ServerPort++
			_, unrelated := f.plan(t, runtimeResourceEncode(t, f, options.Options))
			runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), unrelated))
			_, stableView := f.acquire(t)
			stableRaw, _ := stableView.inbounds.Get("tls")
			component := map[bool]string{true: "certificate-provider:cert", false: "inbound:tls"}[named]
			if stableRaw != oldConsumer || stableView.componentIDs[component] != oldView.componentIDs[component] || issued.Load() != 1 {
				t.Fatal("unchanged certificate allocation was replaced")
			}
			provider.APIToken = "replacement-token"
			blocked, planErr := f.box.planRuntimeConfig(context.Background(), "actor-a", f.identity(), runtimeResourceEncode(t, f, options.Options))
			if planErr != nil || blocked.Applicable || len(blocked.Errors) == 0 || blocked.Errors[0].Code != "RESTART_REQUIRED" || issued.Load() != 1 {
				t.Fatalf("public Plan admitted overlapping active cache: %+v %v", blocked, planErr)
			}
			oldDirectory := provider.DataDirectory
			oldProviderResource := runtimeTestResource(t, f, oldView.componentIDs[map[bool]string{true: "certificate-provider:cert", false: "inbound:tls"}[named]])
			provider.APIToken = "fixture-token"
			provider.Domain = []string{"new.invalid"}
			blocked, planErr = f.box.planRuntimeConfig(context.Background(), "actor-a", f.identity(), runtimeResourceEncode(t, f, options.Options))
			if planErr != nil || blocked.Applicable || len(blocked.Errors) == 0 || blocked.Errors[0].Code != "RESTART_REQUIRED" || issued.Load() != 1 {
				t.Fatalf("domain-only change reused the active provider: %+v %v", blocked, planErr)
			}
			provider.Domain = []string{"old.invalid"}
			provider.DataDirectory = filepath.Join(t.TempDir(), "new")
			directoryOnly, planErr := f.box.planRuntimeConfig(context.Background(), "actor-a", f.identity(), runtimeResourceEncode(t, f, options.Options))
			if planErr != nil || !directoryOnly.Applicable || len(directoryOnly.Errors) != 0 || issued.Load() != 1 {
				t.Fatalf("separate directory was not an inert applicable replacement: %+v %v", directoryOnly, planErr)
			}
			provider.Domain = []string{"new.invalid"}
			provider.APIToken = "replacement-token"
			_, apply := f.plan(t, runtimeResourceEncode(t, f, options.Options))
			operation := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
			if operation.Active.Revision != apply.Expected.Revision+1 {
				t.Fatalf("certificate not published: %+v", operation)
			}
			newLease, newView := f.acquire(t)
			newRaw, _ := newView.inbounds.Get("tls")
			newConsumer := newRaw.(*runtimeCertificateTLSConsumer)
			if oldConsumer == newConsumer {
				t.Fatal("TLS consumer was reused after captured provider replacement")
			}
			runtimeCertificateHandshake(t, newLease, newConsumer, "new.invalid")
			runtimeCertificateHandshake(t, oldLease, oldConsumer, "old.invalid")
			newDirectory := provider.DataDirectory
			provider.DataDirectory = oldDirectory
			blocked, planErr = f.box.planRuntimeConfig(context.Background(), "actor-a", f.identity(), runtimeResourceEncode(t, f, options.Options))
			provider.DataDirectory = newDirectory
			if planErr != nil || blocked.Applicable || len(blocked.Errors) == 0 || blocked.Errors[0].Code != "RESTART_REQUIRED" || issued.Load() != 2 {
				t.Fatalf("public Plan ignored retained old cache allocation: %+v %v", blocked, planErr)
			}
			select {
			case <-oldProviderResource.owner.Closed():
				t.Fatal("old TLS allocation lost its retained provider")
			default:
			}
			if issued.Load() != 2 {
				t.Fatalf("unexpected real issuer count: %d", issued.Load())
			}
			oldLease.Release()
		})
	}
}

func TestRuntimeCertificateClaimsRejectRetainedAliasesListenersAndDNSChallenges(t *testing.T) {
	root := t.TempDir()
	claim := runtimeCertificateClaim{component: "certificate-provider:cert", path: "certificate_providers[0]", directory: filepath.Join(root, "cache"), ports: []uint16{8443}, domains: []string{"a.invalid"}}
	for _, other := range []runtimeCertificateClaim{
		{directory: filepath.Join(root, "cache", "child")},
		{directory: filepath.Join(root, "separate"), ports: []uint16{8443}},
		{listener: true, ports: []uint16{8443}},
		{directory: filepath.Join(root, "separate"), domains: []string{"a.invalid"}},
		{opaque: true},
	} {
		live := []*runtimeResource{{certificateClaims: []runtimeCertificateClaim{other}}}
		problems := runtimeCertificateClaimProblems([]runtimeCertificateClaim{claim}, map[string]bool{claim.component: true}, live)
		if len(problems) != 1 || problems[0].Code != "RESTART_REQUIRED" {
			t.Fatal("retained conflict admitted", problems)
		}
		if problems = runtimeCertificateClaimProblems([]runtimeCertificateClaim{claim}, map[string]bool{}, live); len(problems) != 0 {
			t.Fatal("unchanged exact owner rejected", problems)
		}
	}
	if runtimeCertificateClaimsOverlap(claim, runtimeCertificateClaim{directory: filepath.Join(root, "unrelated")}) {
		t.Fatal("disjoint cache rejected")
	}
}

func TestRuntimeCertificateEffectReportingRemainsSeparateFromDurability(t *testing.T) {
	var events []string
	g := &preparedRuntimeGraph{inlineEffects: []adapter.RuntimeStagedEffect{&runtimeCertificateEffectFixture{events: &events, name: "issued", external: true, stageError: io.ErrUnexpectedEOF, compensationError: errors.New("unconfirmed storage compensation")}}}
	if g.stageRuntimeCertificates(context.Background()) == nil {
		t.Fatal("partial issuance accepted")
	}
	g.compensateRuntimeCertificates()
	box := &Box{runtime: &runtimeCoordinator{}}
	record := &runtimePlanRecord{operation: &RuntimeConfigOperation{Durable: false}}
	box.recordRuntimeCertificateEffects(record, g)
	if len(record.operation.Errors) != 2 || record.operation.Errors[0].Code != "EXTERNAL_EFFECTS_MAY_REMAIN" || record.operation.Errors[1].Code != "CERTIFICATE_COMPENSATION_INCOMPLETE" || record.operation.Durable {
		t.Fatalf("false rollback/durability claim: %+v", record.operation)
	}
}

func TestRuntimeACMEPublicPlanRejectsNativeWorkersBeforePreparation(t *testing.T) {
	for _, dns01 := range []bool{false, true} {
		f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "acme.test"), nil)
		registry := service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry)
		var constructed atomic.Int32
		certificate.Register[option.ACMECertificateProviderOptions](registry, "acme", func(context.Context, log.ContextLogger, string, option.ACMECertificateProviderOptions) (adapter.CertificateProviderService, error) {
			constructed.Add(1)
			return nil, errors.New("must not construct unsupported ACME candidate")
		})
		runtimeResourceNew(t, f, options)
		f.start(t)
		before := f.identity()
		provider := &option.ACMECertificateProviderOptions{Domain: []string{"fixture.invalid"}}
		if dns01 {
			provider.DNS01Challenge = &option.ACMEProviderDNS01ChallengeOptions{Provider: "cloudflare"}
		}
		options.CertificateProviders = []option.CertificateProvider{{Type: "acme", Tag: "cert", Options: provider}}
		plan, err := f.box.planRuntimeConfig(context.Background(), "actor-a", before, runtimeResourceEncode(t, f, options.Options))
		if err != nil || plan.Applicable || len(plan.Errors) == 0 || constructed.Load() != 0 || f.identity() != before {
			t.Fatalf("unsupported ACME native tail reached preparation: %+v %v", plan, err)
		}
		if dns01 {
			found := false
			for _, problem := range plan.Errors {
				if problem.Code == "PENDING_ADAPTER" && problem.Path == "certificate_providers[0].dns01_challenge" {
					found = true
				}
			}
			if !found {
				t.Fatal("DNS01 boundary was not precise", plan.Errors)
			}
		}
		// Original cold startup remains eligible for its legacy lifecycle; only
		// graph selection is fenced. No candidate constructor is called here.
		if runtimeInitialEligible(f.ctx, options) {
			t.Fatal("ACME initial graph bypassed the same public eligibility guard")
		}
	}
}

func TestRuntimeOriginCACanceledActualHTTPStagePreservesGraphAndEffectEvidence(t *testing.T) {
	_, _, serverCert := runtimeCertificateTestSigner(t)
	entered := make(chan struct{}, 1)
	finish := make(chan struct{})
	t.Cleanup(func() { close(finish) })
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "cancel.test"), func(o *runtimeTestSocks) error {
		o.dialHook = func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
			client, peer := net.Pipe()
			go func() {
				defer peer.Close()
				server := stdtls.Server(peer, &stdtls.Config{Certificates: []stdtls.Certificate{serverCert}})
				request, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, request.Body)
				_ = request.Body.Close()
				entered <- struct{}{}
				select {
				case <-ctx.Done():
				case <-finish:
				}
			}()
			return client, nil
		}
		return nil
	})
	originca.RegisterCertificateProvider(service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry))
	runtimeResourceNew(t, f, options)
	f.start(t)
	before := f.identity()
	options.HTTPClients = []option.HTTPClient{{Tag: "issuer", Version: 1, Detour: "a", TLS: &option.OutboundTLSOptions{Insecure: true}}}
	options.CertificateProviders = []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: &option.CloudflareOriginCACertificateProviderOptions{Domain: []string{"fixture.invalid"}, APIToken: "fixture", RequestType: option.CloudflareOriginCARequestTypeOriginECC, DataDirectory: filepath.Join(t.TempDir(), "canceled"), HTTPClient: &option.HTTPClientOptions{Tag: "issuer"}}}}
	_, request := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	ctx, cancel := context.WithCancel(runtimeTestContext(t))
	defer cancel()
	pending := runtimeTestApplyAsync(f, ctx, request)
	select {
	case <-entered:
	case <-runtimeTestContext(t).Done():
		t.Fatal("actual Origin CA stage never entered HTTP request")
	}
	cancel()
	operation := runtimeTestReceiveApply(t, pending)
	if f.identity() != before || operation.Active.Revision > before.Revision {
		t.Fatalf("canceled certificate published: %+v", operation)
	}
	found := false
	for _, problem := range operation.Errors {
		if problem.Code == "EXTERNAL_EFFECTS_MAY_REMAIN" {
			found = true
		}
	}
	if !found {
		t.Fatal("actual issuance cancellation lost external-effect uncertainty", operation.Errors)
	}
}

func TestRuntimeCertificateDirectoryAliasAndPrepareIdentityDriftFailClosed(t *testing.T) {
	root := t.TempDir()
	oldPath, newPath, alias := filepath.Join(root, "old"), filepath.Join(root, "new"), filepath.Join(root, "alias")
	if err := os.MkdirAll(oldPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(oldPath, alias); err != nil {
		t.Skip("platform cannot create private symlink fixture")
	}
	options := option.Options{CertificateProviders: []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: &option.CloudflareOriginCACertificateProviderOptions{DataDirectory: alias}}}}
	claims, err := runtimeCertificateClaims(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	resolvedOld, err := filepath.EvalSymlinks(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].directory != resolvedOld {
		t.Fatal("certificate alias was not canonicalized", claims)
	}
	g := &preparedRuntimeGraph{certificateClaimContext: context.Background(), certificateClaims: claims, options: options}
	if err = g.validateRuntimeCertificateClaims(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(newPath, alias); err != nil {
		t.Fatal(err)
	}
	if g.validateRuntimeCertificateClaims() == nil {
		t.Fatal("stage accepted changed physical certificate directory")
	}
}

func TestRuntimeCertificateRetainedObjectIdentitySurvivesDirectoryRename(t *testing.T) {
	root := t.TempDir()
	oldPath, moved := filepath.Join(root, "old"), filepath.Join(root, "moved")
	if err := os.Mkdir(oldPath, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(oldPath, "existing-child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	options := func(path string) option.Options {
		return option.Options{CertificateProviders: []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: &option.CloudflareOriginCACertificateProviderOptions{DataDirectory: path}}}}
	}
	old, err := runtimeCertificateClaims(context.Background(), options(oldPath))
	if err != nil {
		t.Fatal(err)
	}
	oldChild, err := runtimeCertificateClaims(context.Background(), options(child))
	if err != nil {
		t.Fatal(err)
	}
	missingChild, err := runtimeCertificateClaims(context.Background(), options(filepath.Join(oldPath, "missing-child")))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(oldPath, moved); err != nil {
		t.Fatal(err)
	}
	// Reusing the old name must not change the retained object's snapshot.
	if err = os.Mkdir(oldPath, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{moved, filepath.Join(moved, "existing-child"), filepath.Join(moved, "missing-child")} {
		current, err := runtimeCertificateClaims(context.Background(), options(candidate))
		if err != nil {
			t.Fatal(err)
		}
		if !runtimeCertificateClaimsOverlap(old[0], current[0]) || !runtimeCertificateClaimsOverlap(current[0], old[0]) {
			t.Fatal("renamed retained directory lost exact object exclusion", candidate)
		}
		if candidate == moved && (!runtimeCertificateClaimsOverlap(oldChild[0], current[0]) || !runtimeCertificateClaimsOverlap(current[0], oldChild[0])) {
			t.Fatal("renamed parent lost retained child exclusion")
		}
		if candidate == moved && (!runtimeCertificateClaimsOverlap(missingChild[0], current[0]) || !runtimeCertificateClaimsOverlap(current[0], missingChild[0])) {
			t.Fatal("renamed parent lost missing-leaf ancestor exclusion")
		}
	}
	replacement, err := runtimeCertificateClaims(context.Background(), options(oldPath))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(old[0].object, replacement[0].object) {
		t.Fatal("retained object identity followed its reused pathname")
	}
	unrelated, err := runtimeCertificateClaims(context.Background(), options(filepath.Join(root, "unrelated")))
	if err != nil {
		t.Fatal(err)
	}
	for _, retained := range []runtimeCertificateClaim{old[0], oldChild[0], missingChild[0]} {
		if runtimeCertificateClaimsOverlap(retained, unrelated[0]) || runtimeCertificateClaimsOverlap(unrelated[0], retained) {
			t.Fatal("retained identity incorrectly excluded an unrelated sibling")
		}
	}
}

func TestRuntimeCertificateMissingLeafRejectsReplacedAncestor(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	options := option.Options{CertificateProviders: []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: &option.CloudflareOriginCACertificateProviderOptions{DataDirectory: filepath.Join(parent, "missing", "leaf")}}}}
	claims, err := runtimeCertificateClaims(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	g := &preparedRuntimeGraph{certificateClaimContext: context.Background(), certificateClaims: claims, options: options}
	if err = os.MkdirAll(filepath.Join(parent, "missing", "leaf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = g.validateRuntimeCertificateClaims(); err != nil {
		t.Fatal("creating a leaf beneath its retained ancestor was rejected", err)
	}
	// Keep the initial missing-leaf snapshot to exercise the pre-bind window.
	g.certificateClaims = claims
	if err = os.Rename(parent, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(parent, "missing", "leaf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if g.validateRuntimeCertificateClaims() == nil {
		t.Fatal("missing leaf accepted a replacement for its retained ancestor")
	}
}
