package box

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

const runtimeEligibilitySecret = "private-eligibility-value-must-not-appear"

type runtimeEligibilityFailedOptions struct{}

func (runtimeEligibilityFailedOptions) MarshalJSON() ([]byte, error) {
	return nil, errors.New(runtimeEligibilitySecret)
}

func TestRuntimeInitialEligibilityReasonsPreserveInventory(t *testing.T) {
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	tests := []struct {
		name    string
		options option.Options
		paths   []string
	}{
		{name: "empty"},
		{
			name: "retained TUN cache and plain API",
			options: option.Options{
				Inbounds: []option.Inbound{{Type: "tun", Options: &option.TunInboundOptions{}}},
				Services: []option.Service{{Type: "api", Options: &option.APIServiceOptions{Listen: &listen}}},
				Experimental: &option.ExperimentalOptions{CacheFile: &option.CacheFileOptions{
					Enabled: true, Path: runtimeEligibilitySecret, StoreDNS: true, StoreFakeIP: true,
				}},
			},
		},
		{
			name: "certificate presence",
			options: option.Options{Certificate: &option.CertificateOptions{
				CertificatePath: []string{runtimeEligibilitySecret},
			}},
			paths: []string{"certificate"},
		},
		{
			name:    "empty certificate remains ineligible",
			options: option.Options{Certificate: &option.CertificateOptions{}},
			paths:   []string{"certificate"},
		},
		{
			name:    "network namespace presence",
			options: option.Options{NetworkNamespaces: []option.NetworkNamespace{{Type: "default", Tag: runtimeEligibilitySecret}}},
			paths:   []string{"network_namespaces"},
		},
		{
			name: "all external dashboard dependencies",
			options: option.Options{Experimental: &option.ExperimentalOptions{ClashAPI: &option.ClashAPIOptions{
				ExternalUI: runtimeEligibilitySecret, ExternalUIDownloadURL: runtimeEligibilitySecret,
				ExternalUIDownloadDetour: runtimeEligibilitySecret, Secret: runtimeEligibilitySecret,
			}}},
			paths: []string{"experimental.clash_api.external_ui", "experimental.clash_api.external_ui_download_url", "experimental.clash_api.external_ui_download_detour"},
		},
		{
			name:    "plain clash API is eligible",
			options: option.Options{Experimental: &option.ExperimentalOptions{ClashAPI: &option.ClashAPIOptions{Secret: runtimeEligibilitySecret}}},
		},
		{
			name:    "unsupported inbound remains rejected by compatibility",
			options: option.Options{Inbounds: []option.Inbound{{Type: "direct", Tag: runtimeEligibilitySecret, Options: &option.DirectInboundOptions{}}}},
			paths:   []string{"inbounds[0].lifecycle"},
		},
		{
			name:    "unsupported service remains rejected by compatibility",
			options: option.Options{Services: []option.Service{{Type: "unreviewed", Tag: runtimeEligibilitySecret, Options: &struct{}{}}}},
			paths:   []string{"services"},
		},
		{
			name: "remote source without bootstrap",
			options: option.Options{Route: &option.RouteOptions{RuleSet: []option.RuleSet{{
				Type: "remote", Tag: []string{runtimeEligibilitySecret}, Format: "source",
				RemoteOptions: option.RemoteRuleSet{URL: "https://example.test/" + runtimeEligibilitySecret},
			}}}},
			paths: []string{"route.rule_set[0].initial_path"},
		},
		{
			name: "remote source with bootstrap",
			options: option.Options{Route: &option.RouteOptions{RuleSet: []option.RuleSet{{
				Type: "remote", Tag: []string{runtimeEligibilitySecret}, Format: "source",
				RemoteOptions: option.RemoteRuleSet{URL: "https://example.test/" + runtimeEligibilitySecret, InitialPath: runtimeEligibilitySecret},
			}}}},
		},
		{
			name:    "invalid log level retains compatibility reason",
			options: option.Options{Log: &option.LogOptions{Level: runtimeEligibilitySecret}},
			paths:   []string{"log.level"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			before, err := json.MarshalContext(ctx, test.options)
			if err != nil {
				t.Fatal(err)
			}
			problems := runtimeInitialEligibilityErrors(ctx, Options{Options: test.options})
			var paths []string
			for _, problem := range problems {
				paths = append(paths, problem.Path)
				if problem.Code == "" || problem.Message == "" {
					t.Fatal("initial eligibility reason is incomplete", problem)
				}
			}
			if !reflect.DeepEqual(paths, test.paths) {
				t.Fatalf("reason paths = %v, want %v", paths, test.paths)
			}
			if strings.Contains(fmt.Sprint(problems), runtimeEligibilitySecret) {
				t.Fatal("initial eligibility retained a configuration value")
			}
			eligible := len(test.paths) == 0
			if runtimeInitialEligible(ctx, Options{Options: test.options}) != eligible || RuntimeUsesResourceGraph(ctx, test.options) != eligible {
				t.Fatal("initial eligibility wrappers disagree with the shared inventory")
			}
			after, err := json.MarshalContext(ctx, test.options)
			if err != nil || string(after) != string(before) {
				t.Fatal("initial eligibility mutated its input", err)
			}
		})
	}
}

func TestRuntimeInitialEligibilityDoesNotRetainMarshalError(t *testing.T) {
	options := Options{Outbounds: []option.Outbound{{
		Type: "direct", Tag: runtimeEligibilitySecret, Options: runtimeEligibilityFailedOptions{},
	}}}
	problems := runtimeInitialEligibilityErrors(context.Background(), options)
	if len(problems) != 1 || problems[0].Code != "INITIAL_CONFIG_ENCODING_FAILED" || problems[0].Path != "runtime" || strings.Contains(fmt.Sprint(problems), runtimeEligibilitySecret) {
		t.Fatal("initial encoding diagnostic lost its safe classification", problems)
	}
	if runtimeInitialEligible(context.Background(), options) || RuntimeUsesResourceGraph(context.Background(), options.Options) {
		t.Fatal("encoding failure became eligible")
	}
}

func TestRuntimeLegacyBoxRetainsSanitizedInitialReasons(t *testing.T) {
	_, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.org"), nil)
	options.Certificate = &option.CertificateOptions{}
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	if instance.runtime != nil || len(instance.runtimeEligibilityErrors) != 1 || instance.runtimeEligibilityErrors[0].Path != "certificate" {
		t.Fatal("legacy constructor lost the initial eligibility reason", instance.runtimeEligibilityErrors)
	}
	options.Certificate = nil
	if len(instance.runtimeEligibilityErrors) != 1 || instance.runtimeEligibilityErrors[0].Path != "certificate" {
		t.Fatal("initial eligibility diagnostics still depend on mutable options")
	}
}

func TestRuntimeEligibleConstructionFailureDoesNotFallBack(t *testing.T) {
	failure := errors.New("candidate construction failed")
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.org"), func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "a" {
			return failure
		}
		return nil
	})
	instance, err, _ := NewWithConstructionReport(options)
	if instance != nil || !errors.Is(err, failure) || f.count("a") != 1 {
		t.Fatal("eligible construction failed to preserve its original failure", instance, err, f.count("a"))
	}
}
