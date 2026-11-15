package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func TestCLIResourceDirectoryKeepsProcessWorkingDirectory(t *testing.T) {
	unchanged := context.Background()
	if actual, err := withResourceDirectory(unchanged, ""); err != nil || actual != unchanged {
		t.Fatalf("unset resource directory changed the context: %v", err)
	}
	if runtime.GOOS != "windows" {
		t.Skip("Windows helper resource-directory contract")
	}
	root := t.TempDir()
	resources := filepath.Join(root, "resources")
	protected := filepath.Join(root, "runtime")
	for _, path := range []string{resources, protected} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(resources, "certificate.pem"), []byte("resource"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(protected)
	ctx, err := withResourceDirectory(context.Background(), resources)
	if err != nil {
		t.Fatal(err)
	}
	content, err := filemanager.ReadFile(ctx, "certificate.pem")
	if err != nil || string(content) != "resource" {
		t.Fatalf("resource read = %q, %v", content, err)
	}
	if err := filemanager.WriteFile(ctx, "state", []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(resources, "state")); err != nil {
		t.Fatal(err)
	}
	if current, err := os.Getwd(); err != nil || current != protected {
		t.Fatalf("process cwd = %q, %v; want %q", current, err, protected)
	}
	manager := service.FromContext[filemanager.Manager](ctx)
	manager = &resourceFileManager{directory: `C:\Users\test\Polaris`}
	for _, test := range []struct{ path, expected string }{
		{"", ""},
		{".", `C:\Users\test\Polaris`},
		{`keys\client.pem`, `C:\Users\test\Polaris\keys\client.pem`},
		{`..\client.pem`, `C:\Users\test\client.pem`},
		{`\keys\client.pem`, `C:\keys\client.pem`},
		{`/keys/client.pem`, `C:/keys/client.pem`},
		{`C:keys\client.pem`, `C:\Users\test\Polaris\keys\client.pem`},
		{`c:keys\client.pem`, `C:\Users\test\Polaris\keys\client.pem`},
		{`C:`, `C:\Users\test\Polaris`},
		{`D:keys\client.pem`, `D:\keys\client.pem`},
		{`D:`, `D:\`},
		{`D:\keys\client.pem`, `D:\keys\client.pem`},
		{`\\server\share\client.pem`, `\\server\share\client.pem`},
		{`\\?\C:\keys\client.pem`, `\\?\C:\keys\client.pem`},
	} {
		if actual := manager.BasePath(test.path); actual != test.expected {
			t.Errorf("BasePath(%q) = %q; want %q", test.path, actual, test.expected)
		}
	}
	t.Setenv("POLARIS_RESOURCE_TEST_UNSET", "")
	if actual := manager.BasePath(os.ExpandEnv("$POLARIS_RESOURCE_TEST_UNSET")); actual != "" {
		t.Errorf("expanded empty resource became %q", actual)
	}
	if actual := adapter.ConfigurationDirectoryPath(ctx, ""); actual != resources {
		t.Errorf("empty configuration directory = %q; want %q", actual, resources)
	}
	if actual := adapter.ConfigurationDirectoryPath(context.Background(), ""); actual != "" {
		t.Errorf("unset resource directory changed empty path to %q", actual)
	}
}

// Exercise the real CLI entry-point context and Box constructor, but stop at
// an inert protocol fixture before native Tailscale, filesystem or network IO.
// This is not a native startup-success test. The unpatched CLI reaches the
// fixture but fails registration instead of returning the sentinel.
func TestCLITailscaleRegistrarReachesRuntimeConstructor(t *testing.T) {
	oldContext, oldPaths, oldDirectories := globalCtx, configPaths, configDirectories
	oldWorkingDir, oldDisableColor := workingDir, disableColor
	t.Cleanup(func() {
		globalCtx, configPaths, configDirectories = oldContext, oldPaths, oldDirectories
		workingDir, disableColor = oldWorkingDir, oldDisableColor
	})
	workingDir, disableColor = "", false
	configPaths, configDirectories = []string{"unused-fixture.json"}, nil
	t.Setenv("SUDO_USER", "")
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	preRun(commandRun, nil)

	registry, ok := service.FromContext[adapter.EndpointRegistry](globalCtx).(*endpoint.Registry)
	if !ok {
		t.Fatal("CLI endpoint registry is unavailable")
	}
	sentinel := errors.New("controlled stop before native Tailscale construction")
	var nonces []string
	var cleaned chan struct{}
	var capturedContext context.Context
	var capturedSource adapter.RuntimeResourceSource
	var capturedTag string
	var capturedOptions option.TailscaleEndpointOptions
	endpoint.Register[option.TailscaleEndpointOptions](registry, C.TypeTailscale, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.TailscaleEndpointOptions) (adapter.Endpoint, error) {
		if !adapter.IsRuntimePreparation(ctx) {
			return nil, errors.New("CLI constructor did not use runtime preparation")
		}
		source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
		if !ok {
			return nil, errors.New("CLI constructor lost its resource owner")
		}
		cleanup := cleaned
		var cleanupOnce sync.Once
		if err := adapter.DeferConstructionCleanup(ctx, func() error { cleanupOnce.Do(func() { close(cleanup) }); return nil }); err != nil {
			return nil, err
		}
		// Registry.Create holds its own mutex while calling this constructor.
		// Probe admission with incomplete evidence here (no registrar callback),
		// then validate a full original request after Create has released the lock.
		if _, err := adapter.RegisterRuntimeTailscaleChild(ctx, adapter.RuntimeTailscaleChildRequest{}); err == nil {
			return nil, errors.New("CLI registrar accepted incomplete original evidence")
		} else if !strings.Contains(err.Error(), "incomplete original Tailscale child evidence") {
			return nil, err
		}
		capturedContext = ctx
		capturedSource = source
		capturedTag, capturedOptions = tag, options
		return nil, sentinel
	})
	// preRun is deliberately called only once: reloads reuse the same CLI host.
	for range 2 {
		cleaned = make(chan struct{})
		capturedContext = nil
		options := option.Options{Endpoints: []option.Endpoint{{Type: C.TypeTailscale, Tag: "cli-fixture", Options: &option.TailscaleEndpointOptions{OnDemand: true}}}}
		instance, cancel, err := create(options, nil)
		if cancel != nil {
			cancel()
		}
		if instance != nil {
			_ = instance.CloseWithResult()
			t.Fatal("inert constructor unexpectedly produced a running Box")
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("CLI did not reach the registered inert constructor boundary: %v", err)
		}
		select {
		case <-cleaned:
		case <-time.After(5 * time.Second):
			t.Fatal("original constructor cleanup did not complete")
		}
		if capturedContext == nil {
			t.Fatal("CLI did not preserve the constructor context")
		}
		// Check the exact captured values outside Registry.Create's mutex. This
		// request is an inert test birth, not a claim that the aborted Box started.
		constructionDone, closeDone, observed := make(chan struct{}), make(chan struct{}), make(chan struct{})
		close(constructionDone)
		close(closeDone)
		registrationContext := adapter.ContextWithRuntimeTailscaleChildBase(capturedContext, context.Background())
		registration, err := adapter.RegisterRuntimeTailscaleChild(registrationContext, adapter.RuntimeTailscaleChildRequest{
			ResourceID: capturedSource.ID(), Generation: 1, Tag: capturedTag,
			StateDirectory: capturedOptions.StateDirectory, TaildropDirectory: capturedOptions.TaildropDirectory,
			ConstructionDone: constructionDone, CloseDone: closeDone,
			ConstructionResult: func() error { return sentinel },
			CloseResult:        func() error { close(observed); return nil },
			StoreScopes:        func() []adapter.TailscaleStoreNode { return nil },
			DirectoryScopes:    func() []adapter.TailscaleDirectoryNode { return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		canonical, captured := adapter.RuntimeTailscaleConfiguration(capturedContext)
		binding := service.PtrFromContext[adapter.TailscaleStoreRunBinding](registration.Context())
		digest := sha256.Sum256(canonical)
		if !captured || binding == nil || len(binding.RunNonce) != 64 || binding.ConfigDigest != hex.EncodeToString(digest[:]) {
			t.Fatal("CLI registration lost original configuration identity")
		}
		nonces = append(nonces, binding.RunNonce)
		select {
		case <-observed:
		case <-time.After(5 * time.Second):
			t.Fatal("original close observation did not execute")
		}
	}
	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatal("CLI reload reused an original child birth identity")
	}
}
