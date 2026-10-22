package box

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

// Observe the production policy call rather than disabling deprecation checks
// with an environment variable or changing the global compiled version.
type legacyHTTPDeprecationObserver struct{ implicit atomic.Int32 }

func (o *legacyHTTPDeprecationObserver) ReportDeprecated(note deprecated.Note) {
	if note.Name == deprecated.OptionImplicitDefaultHTTPClient.Name {
		o.implicit.Add(1)
	}
}

func legacyHTTPBoxOptions(t *testing.T) (Options, *legacyHTTPDeprecationObserver) {
	t.Helper()
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "before.example"), nil)
	direct.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	// A real direct listener deliberately selects legacy construction. It is
	// loopback/ephemeral and needs no TUN, namespace or host-network privileges.
	options.Inbounds = []option.Inbound{{Type: C.TypeDirect, Tag: "legacy-direct", Options: &option.DirectInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &listen}, Network: "tcp",
	}}}
	options.Outbounds = append(options.Outbounds, option.Outbound{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}})
	// Use a real selector for explicit detours. A detour to an otherwise
	// empty direct outbound is intentionally rejected by the production dialer.
	options.Outbounds = append(options.Outbounds, option.Outbound{Type: C.TypeSelector, Tag: "local-http", Options: &option.SelectorOutboundOptions{
		Outbounds: []string{"direct"}, Default: "direct",
	}})
	options.Route.Final = "direct"
	observer := new(legacyHTTPDeprecationObserver)
	options.Context = service.ContextWith[deprecated.Manager](options.Context, observer)
	return options, observer
}

func constructLegacyHTTPBox(t *testing.T, options Options) *Box {
	t.Helper()
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.CloseWithResult(); err != nil {
			t.Errorf("legacy box cleanup: %v", err)
		}
	})
	if instance.runtime != nil {
		t.Fatal("test must exercise the real legacy lifecycle, not the HOT shortcut")
	}
	return instance
}

func TestLegacyBoxWithoutHTTPConsumerDoesNotUseImplicitDefault(t *testing.T) {
	options, observer := legacyHTTPBoxOptions(t)
	instance := constructLegacyHTTPBox(t, options)
	if observer.implicit.Load() != 0 {
		t.Fatal("construction resolved an unused implicit HTTP client")
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	if observer.implicit.Load() != 0 {
		t.Fatal("legacy startup reported implicit HTTP without an HTTP consumer")
	}
}

func TestLegacyBoxExplicitHTTPDefaultValidation(t *testing.T) {
	for _, missing := range []bool{false, true} {
		name := "configured"
		if missing {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			options, observer := legacyHTTPBoxOptions(t)
			options.Route.DefaultHTTPClient = "explicit"
			if !missing {
				options.HTTPClients = []option.HTTPClient{{Tag: "explicit", DialerOptions: option.DialerOptions{Detour: "local-http"}}}
			}
			instance := constructLegacyHTTPBox(t, options)
			err := instance.Start()
			if missing {
				if err == nil || !strings.Contains(err.Error(), "http_client not found: explicit") {
					t.Fatalf("missing explicit default must still fail: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if observer.implicit.Load() != 0 {
				t.Fatal("explicit default incorrectly used implicit fallback")
			}
		})
	}
}

func TestLegacyBoxRemoteRuleSetHTTPPolicy(t *testing.T) {
	for _, mode := range []string{"inline", "named", "configured-default", "implicit-default", "unknown-named", "initial-inline", "initial-implicit"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"version":%d,"rules":[{"domain_suffix":["before.example"]}]}`, C.RuleSetVersionCurrent)
			}))
			t.Cleanup(server.Close)
			options, observer := legacyHTTPBoxOptions(t)
			remote := option.RemoteRuleSet{URL: server.URL + "/rules.json"}
			switch mode {
			case "inline", "initial-inline":
				remote.HTTPClient = &option.HTTPClientOptions{DialerOptions: option.DialerOptions{Detour: "local-http"}}
			case "named", "configured-default":
				options.HTTPClients = []option.HTTPClient{{Tag: "explicit", DialerOptions: option.DialerOptions{Detour: "local-http"}}}
				if mode == "named" {
					remote.HTTPClient = &option.HTTPClientOptions{Tag: "explicit"}
				} else {
					options.Route.DefaultHTTPClient = "explicit"
				}
			case "unknown-named":
				remote.HTTPClient = &option.HTTPClientOptions{Tag: "unknown"}
			}
			if strings.HasPrefix(mode, "initial-") {
				remote.InitialPath = filepath.Join(t.TempDir(), "rules.json")
				content := fmt.Sprintf(`{"version":%d,"rules":[{"domain_suffix":["before.example"]}]}`, C.RuleSetVersionCurrent)
				if err := os.WriteFile(remote.InitialPath, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			options.Route.RuleSet = []option.RuleSet{{Type: C.RuleSetTypeRemote, Tag: []string{"sites"}, Format: C.RuleSetFormatSource, RemoteOptions: remote}}
			instance := constructLegacyHTTPBox(t, options)
			if observer.implicit.Load() != 0 || requests.Load() != 0 {
				t.Fatal("construction performed HTTP or resolved the implicit default")
			}
			var err error
			if remote.InitialPath != "" {
				// PreStart resolves the consumer and loads initial_path before
				// PostStart starts the independent remote-update worker.
				err = instance.PreStart()
			} else {
				err = instance.Start()
			}
			if mode == "unknown-named" {
				if err == nil || !strings.Contains(err.Error(), "http_client not found: unknown") {
					t.Fatalf("unknown named consumer must fail without fallback: %v", err)
				}
				if requests.Load() != 0 {
					t.Fatal("invalid consumer reached the network")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				wantRequests := int32(1)
				if remote.InitialPath != "" {
					wantRequests = 0
				}
				if requests.Load() != wantRequests {
					t.Fatalf("loopback rule-set fetches = %d, want %d", requests.Load(), wantRequests)
				}
			}
			var wantDeprecated int32
			if mode == "implicit-default" || mode == "initial-implicit" {
				wantDeprecated = 1
			}
			if got := observer.implicit.Load(); got != wantDeprecated {
				t.Fatalf("implicit default policy calls = %d, want %d", got, wantDeprecated)
			}
		})
	}
}

func TestLegacyBoxHTTPDeprecationProcessBoundary(t *testing.T) {
	if runtime.GOOS == "android" {
		t.Skip("Android system certificate boundary requires its own platform fixture")
	}
	const helperEnv = "POLARIS_TEST_LEGACY_HTTP_POLICY"
	if mode := os.Getenv(helperEnv); mode != "" {
		// Only the isolated child changes the compile-time version variable;
		// the parent and unrelated tests keep their actual build identity.
		C.Version = "1.15.0-polaris-alpha.12.1"
		options, _ := legacyHTTPBoxOptions(t)
		options.Context = service.ContextWith[deprecated.Manager](options.Context, deprecated.NewStderrManager(log.StdLogger()))
		if mode != "unused" {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `{"version":%d,"rules":[]}`, C.RuleSetVersionCurrent)
			}))
			t.Cleanup(server.Close)
			remote := option.RemoteRuleSet{URL: server.URL + "/rules.json"}
			if mode == "inline" {
				remote.HTTPClient = &option.HTTPClientOptions{DialerOptions: option.DialerOptions{Detour: "local-http"}}
			}
			options.Route.RuleSet = []option.RuleSet{{Type: C.RuleSetTypeRemote, Tag: []string{"sites"}, Format: C.RuleSetFormatSource, RemoteOptions: remote}}
		}
		instance := constructLegacyHTTPBox(t, options)
		if err := instance.Start(); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, mode := range []string{"unused", "inline", "implicit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLegacyBoxHTTPDeprecationProcessBoundary$", "-test.v")
			for _, entry := range os.Environ() {
				if strings.HasPrefix(entry, helperEnv+"=") || strings.HasPrefix(entry, "ENABLE_DEPRECATED_IMPLICIT_DEFAULT_HTTP_CLIENT=") {
					continue
				}
				command.Env = append(command.Env, entry)
			}
			command.Env = append(command.Env, helperEnv+"="+mode)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("policy child did not complete: %v\n%s", ctx.Err(), output)
			}
			if mode == "implicit" {
				var exitError *exec.ExitError
				if !errors.As(err, &exitError) || exitError.ExitCode() != 1 || !strings.Contains(string(output), "ENABLE_DEPRECATED_IMPLICIT_DEFAULT_HTTP_CLIENT=true") {
					t.Fatalf("actual implicit consumer must retain the production fatal policy, got %v\n%s", err, output)
				}
			} else if err != nil {
				t.Fatalf("legacy %s must start with the real stderr policy: %v\n%s", mode, err, output)
			} else if strings.Contains(string(output), "implicit default HTTP client") {
				t.Fatalf("legacy %s reported an unused default:\n%s", mode, output)
			}
		})
	}
}
