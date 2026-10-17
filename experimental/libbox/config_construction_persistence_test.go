package libbox

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func fixtureConfig(t *testing.T, services []map[string]any) string {
	t.Helper()
	data, err := stdjson.Marshal(map[string]any{
		"log":      map[string]any{"disabled": true},
		"inbounds": []map[string]any{{"type": "shadowsocks", "tag": "managed", "method": "aes-128-gcm", "managed": true}},
		"services": services,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func unchangedFile(t *testing.T, path string, before []byte) {
	t.Helper()
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("construction changed file: %s / %v", after, err)
	}
}

func TestRealSSMCachePreservedByLegacyTypedFailureReplacementAndCancellation(t *testing.T) {
	for _, operation := range []string{"complete", "later-constructor-failure", "replace", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.json")
			before := []byte(`{"endpoints":{"/probe":{"global_uplink":123,"users":{"alice":"persist-me"}}}}`)
			if err := os.WriteFile(path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			ssm := map[string]any{"type": "ssm-api", "tag": "cache", "cache_path": path, "servers": map[string]string{"/probe": "managed"}}
			services := []map[string]any{ssm}
			if operation == "later-constructor-failure" {
				services = append(services, map[string]any{"type": "ssm-api", "tag": "failure", "servers": map[string]string{"/bad": "missing-inbound"}})
			}
			if operation == "replace" {
				services = append(services, ssm)
			}
			config := fixtureConfig(t, services)
			if operation != "cancel" {
				legacyErr := CheckConfig(config)
				result := CheckConfigWithResult(config, "real-ssm-"+operation, 1000)
				want := "Accepted"
				// A repeated tag is a constructor failure too: managers reject it
				// instead of replacing the earlier object.
				if operation == "later-constructor-failure" || operation == "replace" {
					want = "Rejected"
				}
				if result.validation != want || result.cleanup != "CleanupUnknown" {
					t.Fatalf("result = %+v", result)
				}
				if want == "Accepted" && legacyErr != nil {
					t.Fatalf("cleanup changed legacy acceptance: %v", legacyErr)
				}
				if want == "Rejected" && (legacyErr == nil || result.validationError != legacyErr.Error()) {
					t.Fatalf("legacy rejection changed: %v / %s", legacyErr, result.validationError)
				}
			} else {
				result := checkConfigWithResult(config, "real-ssm-cancel", 1000, func(ctx context.Context, options option.Options) (error, error) {
					ctx, cancel := context.WithCancel(ctx)
					defer cancel()
					registry := service.FromContext[adapter.ServiceRegistry](ctx).(*boxService.Registry)
					boxService.Register[struct{}](registry, "cancel-after-cache", func(context.Context, log.ContextLogger, string, struct{}) (adapter.Service, error) {
						cancel()
						return nil, context.Canceled
					})
					options.Services = append(options.Services, option.Service{Type: "cancel-after-cache", Tag: "cancel"})
					return constructAndDisposeConfig(ctx, options)
				})
				if result.validation != "Rejected" || result.cleanup != "CleanupUnknown" || !strings.Contains(result.validationError, "context canceled") {
					t.Fatalf("cancel = %+v", result)
				}
			}
			unchangedFile(t, path, before)
		})
	}
}

func TestLegacyAcceptedConfigIgnoresIndependentCleanupUnknown(t *testing.T) {
	config := `{"log":{"disabled":true},"inbounds":[{"type":"mixed","tag":"unstarted"}]}`
	result := CheckConfigWithResult(config, "legacy-accepted", 1000)
	if result.validation != "Accepted" || result.cleanup != "CleanupUnknown" || result.cleanupError != "" {
		t.Fatalf("result = %+v", result)
	}
	if err := CheckConfig(config); err != nil {
		t.Fatalf("legacy acceptance changed by cleanup error: %v", err)
	}
}

func TestOptionalRegistryTypesRemainConservativeAcrossBuildTags(t *testing.T) {
	for _, kind := range []string{"ccm", "ocm"} {
		t.Run(kind, func(t *testing.T) {
			credentials := filepath.Join(t.TempDir(), "credentials.json")
			content := `{"claudeAiOauth":{"accessToken":"isolated-test"}}`
			if kind == "ocm" {
				content = `{"OPENAI_API_KEY":"isolated-test"}`
			}
			if err := os.WriteFile(credentials, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			config := fixtureConfig(t, []map[string]any{{"type": kind, "credential_path": credentials, "detour": "unused-isolated-detour"}})
			result := CheckConfigWithResult(config, "registry-"+kind, 1000)
			if result.cleanup != "CleanupUnknown" {
				t.Fatalf("optional constructor promoted cleanup: %+v", result)
			}
			if result.validation != "Accepted" && (result.validation != "Rejected" || !strings.Contains(result.validationError, "not included in this build")) {
				t.Fatalf("unexpected registry result: %+v", result)
			}
		})
	}
}
