package box

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
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
				Services: []option.Service{{Type: "api", Options: &option.APIServiceOptions{ListenOptions: option.ListenOptions{Listen: &listen}}}},
				Experimental: &option.ExperimentalOptions{CacheFile: &option.CacheFileOptions{
					Enabled: true, Path: runtimeEligibilitySecret, StoreDNS: true, StoreFakeIP: true,
				}},
			},
		},
		{
			name: "certificate file shape",
			options: option.Options{Certificate: &option.CertificateOptions{
				CertificatePath: []string{runtimeEligibilitySecret},
			}},
		},
		{
			name:    "empty certificate uses the existing system snapshot adapter",
			options: option.Options{Certificate: &option.CertificateOptions{}},
		},
		{
			name: "inline certificate shape",
			options: option.Options{Certificate: &option.CertificateOptions{
				Certificate: []string{runtimeEligibilitySecret},
			}},
		},
		{
			name:    "explicit system certificate store",
			options: option.Options{Certificate: &option.CertificateOptions{Store: C.CertificateStoreSystem}},
		},
		{
			name:    "Mozilla certificate snapshot adapter",
			options: option.Options{Certificate: &option.CertificateOptions{Store: C.CertificateStoreMozilla}},
		},
		{
			name:    "Chrome certificate snapshot adapter",
			options: option.Options{Certificate: &option.CertificateOptions{Store: C.CertificateStoreChrome}},
		},
		{
			name:    "empty custom certificate snapshot adapter",
			options: option.Options{Certificate: &option.CertificateOptions{Store: C.CertificateStoreNone}},
		},
		{
			name:    "unknown certificate store remains ineligible",
			options: option.Options{Certificate: &option.CertificateOptions{Store: runtimeEligibilitySecret}},
			paths:   []string{"certificate.store"},
		},
		{
			name: "certificate directory remains ineligible",
			options: option.Options{Certificate: &option.CertificateOptions{
				CertificateDirectoryPath: []string{runtimeEligibilitySecret},
			}},
			paths: []string{"certificate.certificate_directory_path"},
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
	options.Certificate = &option.CertificateOptions{Store: C.CertificateStoreNone, CertificateDirectoryPath: []string{t.TempDir()}}
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	if instance.runtime != nil || len(instance.runtimeEligibilityErrors) != 1 || instance.runtimeEligibilityErrors[0].Path != "certificate.certificate_directory_path" {
		t.Fatal("legacy constructor lost the initial eligibility reason", instance.runtimeEligibilityErrors)
	}
	options.Certificate = nil
	if len(instance.runtimeEligibilityErrors) != 1 || instance.runtimeEligibilityErrors[0].Path != "certificate.certificate_directory_path" {
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

func TestRuntimeInitialCertificateLoadFailuresDoNotPublishOrFallBack(t *testing.T) {
	invalidPath := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalidPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		options  option.CertificateOptions
		eligible bool
	}{
		{"invalid inline PEM", option.CertificateOptions{Store: C.CertificateStoreNone, Certificate: []string{"not a certificate"}}, true},
		{"invalid file PEM", option.CertificateOptions{Store: C.CertificateStoreNone, CertificatePath: []string{invalidPath}}, true},
		{"missing certificate file", option.CertificateOptions{Store: C.CertificateStoreNone, CertificatePath: []string{filepath.Join(t.TempDir(), "missing.pem")}}, true},
		{"unknown certificate store", option.CertificateOptions{Store: "unavailable-store"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "certificate.test"), nil)
			options.Certificate = &test.options
			if runtimeInitialEligible(f.ctx, options) != test.eligible {
				t.Fatal("certificate shape selected the wrong construction path")
			}
			instance, err, report := NewWithConstructionReport(options)
			if instance != nil {
				t.Cleanup(func() {
					if err := instance.CloseWithResult(); err != nil {
						t.Error(err)
					}
				})
			}
			if instance != nil || err == nil || !report.Attempted || report.CleanupError != nil || f.count("a") != 0 || f.count("b") != 0 {
				t.Fatal("invalid root input published, leaked construction or reached consumers", instance, err, report)
			}
		})
	}
}

func TestRuntimeInitialCertificateConsumerFailureDoesNotFallBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, r3SourceRootPEM(t, 1), 0o600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("certificate consumer construction failed")
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "certificate.test"), func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "a" {
			return failure
		}
		return nil
	})
	options.Certificate = &option.CertificateOptions{Store: C.CertificateStoreNone, CertificatePath: []string{path}}
	instance, err, report := NewWithConstructionReport(options)
	if instance != nil {
		t.Cleanup(func() {
			if err := instance.CloseWithResult(); err != nil {
				t.Error(err)
			}
		})
	}
	if instance != nil || !errors.Is(err, failure) || !report.Attempted || report.CleanupError != nil || f.count("a") != 1 {
		t.Fatal("eligible root consumer failure fell back or lost watcher cleanup", instance, err, report, f.count("a"))
	}
}
