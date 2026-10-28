package box

import (
	"context"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestRuntimeOmittedDefaultsPreserveSourceOrderNotSortedNodes(t *testing.T) {
	content := strings.Replace(string(runtimeTestConfig(1080, "example.org")), `,"final":"resolver"`, "", 1)
	content = strings.Replace(content, `"final":"select",`, "", 1)
	content = strings.ReplaceAll(content, `"tag":"a"`, `"tag":"z-first"`)
	content = strings.ReplaceAll(content, `"a"`, `"z-first"`)
	f := newRuntimeTestFixture(t, []byte(content), nil)
	f.start(t)
	_, view := f.acquire(t)
	if view.outbounds.Default().Tag() != "z-first" {
		t.Fatal("dependency sorting changed implicit first outbound")
	}
	if view.transports.Default().Tag() != "resolver" {
		t.Fatal("implicit DNS default changed")
	}
}

func TestRuntimeImplicitFallbacksAreDetachedGraphMembers(t *testing.T) {
	original := option.Options{}
	normalized := runtimeResolveGraphDefaults(original)
	if original.Route != nil || original.DNS != nil || len(original.Outbounds) != 0 {
		t.Fatal("normalization mutated source snapshot")
	}
	if len(normalized.Outbounds) != 1 || normalized.Outbounds[0].Type != C.TypeDirect || normalized.Route.Final != "direct" {
		t.Fatal("direct fallback changed")
	}
	if len(normalized.DNS.Servers) != 1 || normalized.DNS.Servers[0].Type != C.DNSTypeLocal || normalized.DNS.Final != "local" {
		t.Fatal("local fallback changed")
	}
}

func TestRuntimeExplicitMissingDefaultDoesNotGainFallback(t *testing.T) {
	options := option.Options{Route: &option.RouteOptions{Final: "missing"}, DNS: &option.DNSOptions{}}
	options.DNS.Final = "missing"
	normalized := runtimeResolveGraphDefaults(options)
	if len(normalized.Outbounds) != 0 || len(normalized.DNS.Servers) != 0 {
		t.Fatal("explicit missing final silently gained fallback")
	}
}

func TestRuntimeImplicitDirectAndLocalAreEligibleWithoutPresenceExceptions(t *testing.T) {
	if _, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), option.Options{}); len(problems) != 0 {
		t.Fatal(problems)
	}
}

func TestRuntimeExplicitLocalAndMDNSAreEligible(t *testing.T) {
	for _, kind := range []string{C.DNSTypeLocal, C.DNSTypeMDNS} {
		options := option.Options{DNS: &option.DNSOptions{Servers: []option.DNSServerOptions{{Type: kind}}}}
		if _, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options); len(problems) != 0 {
			t.Fatal(kind, problems)
		}
	}
}

func TestRuntimeWireGuardEndpointEligibilityIsNotBlanketStructural(t *testing.T) {
	options := option.Options{Endpoints: []option.Endpoint{{Type: C.TypeWireGuard, Options: &option.WireGuardEndpointOptions{}}}}
	_, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{"endpoints":[]}`), options)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
}

func TestRuntimeLogLevelIsDailyButOutputRemainsStructural(t *testing.T) {
	before := []byte(`{"log":{"level":"info","output":"stderr"}}`)
	after := []byte(`{"log":{"level":"debug","output":"stderr"}}`)
	options := option.Options{Log: &option.LogOptions{Level: "debug", Output: "stderr"}}
	if _, problems := runtimeConfigCompatibility(context.Background(), before, after, options); len(problems) != 0 {
		t.Fatal(problems)
	}
	after = []byte(`{"log":{"level":"debug","output":"stdout"}}`)
	_, problems := runtimeConfigCompatibility(context.Background(), before, after, options)
	if len(problems) != 1 || problems[0].Code != "RESTART_REQUIRED" || problems[0].Path != "log.output" {
		t.Fatal(problems)
	}
}
