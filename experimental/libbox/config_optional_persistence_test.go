//go:build with_ccm && with_ocm

package libbox

import (
	"context"
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

func TestOptionalRealServicesPreserveUsageAcrossConstructionPaths(t *testing.T) {
	for _, kind := range []string{"ccm", "ocm"} {
		for _, operation := range []string{"complete", "replace", "later-constructor-failure", "cancel"} {
			t.Run(kind+"/"+operation, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "usage.json")
				before := []byte(`{"last_updated":"2026-09-30T00:00:00Z","combinations":[{"model":"probe","total":{"input_tokens":41},"by_user":{}}]}`)
				if err := os.WriteFile(path, before, 0o600); err != nil {
					t.Fatal(err)
				}
				credentials := filepath.Join(t.TempDir(), "credentials.json")
				content := `{"claudeAiOauth":{"accessToken":"isolated-test"}}`
				if kind == "ocm" {
					content = `{"OPENAI_API_KEY":"isolated-test"}`
				}
				if err := os.WriteFile(credentials, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				settings := map[string]any{"type": kind, "tag": "usage", "credential_path": credentials, "usages_path": path, "detour": "unused-isolated-detour"}
				services := []map[string]any{settings}
				if operation == "replace" {
					services = append(services, settings)
				}
				if operation == "later-constructor-failure" {
					services = append(services, map[string]any{"type": "ssm-api", "tag": "failure", "servers": map[string]string{"/bad": "missing"}})
				}
				config := fixtureConfig(t, services)
				if operation == "cancel" {
					result := checkConfigWithResult(config, kind+"-cancel", 1000, func(ctx context.Context, options option.Options) (error, error) {
						ctx, cancel := context.WithCancel(ctx)
						defer cancel()
						registry := service.FromContext[adapter.ServiceRegistry](ctx).(*boxService.Registry)
						boxService.Register[struct{}](registry, "cancel-after-usage", func(context.Context, log.ContextLogger, string, struct{}) (adapter.Service, error) {
							cancel()
							return nil, context.Canceled
						})
						options.Services = append(options.Services, option.Service{Type: "cancel-after-usage", Tag: "cancel"})
						return constructAndDisposeConfig(ctx, options)
					})
					if result.validation != "Rejected" || result.cleanup != "CleanupUnknown" || !strings.Contains(result.validationError, "context canceled") {
						t.Fatalf("cancel = %+v", result)
					}
				} else {
					legacy := CheckConfig(config)
					result := CheckConfigWithResult(config, kind+"-"+operation, 1000)
					want := "Accepted"
					// A repeated tag is a constructor failure too: managers reject
					// it instead of replacing the earlier object.
					if operation == "later-constructor-failure" || operation == "replace" {
						want = "Rejected"
					}
					if result.validation != want || result.cleanup != "CleanupUnknown" {
						t.Fatalf("result = %+v", result)
					}
					if want == "Accepted" && legacy != nil {
						t.Fatal(legacy)
					}
					if want == "Rejected" && (legacy == nil || legacy.Error() != result.validationError) {
						t.Fatalf("rejection changed: %v / %s", legacy, result.validationError)
					}
				}
				unchangedFile(t, path, before)
			})
		}
	}
}
