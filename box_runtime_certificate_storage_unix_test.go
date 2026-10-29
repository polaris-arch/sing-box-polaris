//go:build unix

package box

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	originca "github.com/sagernet/sing-box/service/origin_ca"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/caddyserver/certmagic"
	"golang.org/x/sys/unix"
)

// This constructor-context wrapper acts only after the real MkdirAll returns.
// It exercises the actual stage acquisition boundary without a production hook.
type runtimeCertificateMkdirBoundary struct {
	filemanager.Manager
	target string
	once   sync.Once
	after  func() error
	err    error
}

func (m *runtimeCertificateMkdirBoundary) MkdirAll(name string, mode os.FileMode) error {
	if err := m.Manager.MkdirAll(name, mode); err != nil {
		return err
	}
	if name == m.target {
		m.once.Do(func() { m.err = m.after() })
	}
	return m.err
}

func TestRuntimeCertificateUnsafeStorageStageHasFiniteOwnerAndNoHTTP(t *testing.T) {
	if mode := os.Getenv("POLARIS_TEST_BOX_ORIGIN_IO_MODE"); mode != "" {
		dir := os.Getenv("POLARIS_TEST_BOX_ORIGIN_IO_DIR")
		var httpCalls, constructed atomic.Int64
		var boundary atomic.Bool
		f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "unsafe-storage.test"), func(o *runtimeTestSocks) error {
			o.dialHook = func(context.Context, string, M.Socksaddr) (net.Conn, error) {
				httpCalls.Add(1)
				return nil, errors.New("unsafe storage reached HTTP transport")
			}
			return nil
		})
		registry := service.FromContext[adapter.CertificateProviderRegistry](f.ctx).(*certificate.Registry)
		certificate.Register[option.CloudflareOriginCACertificateProviderOptions](registry, "cloudflare-origin-ca", func(ctx context.Context, logger log.ContextLogger, tag string, value option.CloudflareOriginCACertificateProviderOptions) (adapter.CertificateProviderService, error) {
			constructed.Add(1)
			ctx = filemanager.WithDefault(ctx, "", "", os.Getuid(), os.Getgid())
			manager := &runtimeCertificateMkdirBoundary{Manager: service.FromContext[filemanager.Manager](ctx), target: value.DataDirectory}
			manager.after = func() error {
				boundary.Store(true)
				if mode == "root" {
					if err := os.Rename(dir, dir+"-retained"); err != nil {
						return err
					}
					return unix.Mkfifo(dir, 0o600)
				}
				issuer := "cloudflare-origin-ca-" + string(option.CloudflareOriginCARequestTypeOriginECC)
				resource := certmagic.CertificateResource{SANs: value.Domain}
				key := certmagic.StorageKeys.SitePrivateKey(issuer, resource.NamesKey())
				if mode == "lock" {
					lockKey := "cloudflare-origin-ca/" + certmagic.StorageKeys.Safe(issuer) + "/" + certmagic.StorageKeys.Safe(resource.NamesKey())
					key = path.Join("locks", certmagic.StorageKeys.Safe(lockKey)+".lock")
				}
				name := filepath.Join(dir, filepath.FromSlash(key))
				if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
					return err
				}
				return unix.Mkfifo(name, 0o600)
			}
			return originca.NewCertificateProvider(service.ContextWith[filemanager.Manager](ctx, manager), logger, tag, value)
		})
		instance, err := New(options)
		if err != nil {
			t.Fatal(err)
		}
		f.box = instance
		// Unknown Root ownership is deliberately retained until this actual
		// child exits. The parent kills+Waits even a broken old implementation.
		t.Cleanup(func() { _ = instance.CloseWithResult() })
		f.start(t)
		before := f.identity()
		provider := &option.CloudflareOriginCACertificateProviderOptions{Domain: []string{"unsafe.invalid"}, DataDirectory: dir, APIToken: "fixture", RequestType: option.CloudflareOriginCARequestTypeOriginECC, HTTPClient: &option.HTTPClientOptions{Tag: "issuer"}}
		options.HTTPClients = []option.HTTPClient{{Tag: "issuer", Version: 1, Detour: "a"}}
		options.CertificateProviders = []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "unsafe", Options: provider}}
		_, apply := f.plan(t, runtimeResourceEncode(t, f, options.Options))
		operation := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
		if !boundary.Load() || constructed.Load() != 1 || operation.Active != before || f.identity() != before || httpCalls.Load() != 0 || len(operation.Errors) == 0 {
			t.Fatal("unsafe real stage was published/reached HTTP/missed boundary", operation, boundary.Load(), constructed.Load(), httpCalls.Load())
		}
		if mode == "root" {
			return
		}
		var held *runtimeResource
		instance.runtime.access.Lock()
		for _, resource := range instance.runtime.catalog {
			for _, claim := range resource.certificateClaims {
				if claim.component == "certificate-provider:unsafe" {
					held = resource
				}
			}
		}
		instance.runtime.access.Unlock()
		if held == nil || held.owner.WaitClosed(runtimeTestContext(t)) == nil {
			t.Fatal("unsafe reader lost UnknownCleanup resource")
		}
		actual, err := certificate.RuntimeDirectoryIdentity(dir)
		if err != nil {
			t.Fatal(err)
		}
		retainsIdentity := false
		instance.runtime.access.Lock()
		instance.runtime.pruneRuntimeCatalogLocked()
		for _, claim := range held.certificateClaims {
			retainsIdentity = retainsIdentity || claim.object != nil && os.SameFile(claim.object, actual)
		}
		retained := instance.runtime.catalog[held.id] != nil
		instance.runtime.access.Unlock()
		if !retained || !retainsIdentity {
			t.Fatal("unsafe reader dropped actual/history root claim", retained, retainsIdentity)
		}
		options.CertificateProviders[0].Tag = "next"
		plan, err := instance.planRuntimeConfig(context.Background(), "actor-a", before, runtimeResourceEncode(t, f, options.Options))
		if err != nil || plan.Applicable || len(plan.Errors) == 0 || plan.Errors[0].Code != "RESTART_REQUIRED" || constructed.Load() != 1 {
			t.Fatal("public Plan ignored unsafe retained owner", plan, err, constructed.Load())
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"root", "cache", "lock"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRuntimeCertificateUnsafeStorageStageHasFiniteOwnerAndNoHTTP$")
			cmd.Env = append(os.Environ(), "POLARIS_TEST_BOX_ORIGIN_IO_MODE="+mode, "POLARIS_TEST_BOX_ORIGIN_IO_DIR="+filepath.Join(t.TempDir(), "cache"))
			cmd.WaitDelay = time.Second
			output, runErr := cmd.CombinedOutput()
			if runErr != nil {
				t.Fatalf("actual stage did not reject/join in finite owner: %v context=%v output=%s", runErr, ctx.Err(), output)
			}
		})
	}
}
