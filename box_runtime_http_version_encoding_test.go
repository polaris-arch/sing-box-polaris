package box

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/option"
	protocolHTTP "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// This reconstructs the failing shape without user credentials: an actual
// HTTP-TLS outbound with explicit version 1, parsed before initial graph choice.
// It uses the production HTTP constructor and issues no network operation.
func runtimeHTTPVersionEncodingConfig(t *testing.T, version int) []byte {
	t.Helper()
	var root map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(runtimeTestConfig(1080, "http-version.test"), &root); err != nil {
		t.Fatal(err)
	}
	var outbounds []stdjson.RawMessage
	if err := stdjson.Unmarshal(root["outbounds"], &outbounds); err != nil {
		t.Fatal(err)
	}
	outbounds = append(outbounds, stdjson.RawMessage(fmt.Sprintf(`{"type":"http","tag":"http-tls","server":"192.0.2.10","server_port":443,"version":%d,"tls":{"enabled":true,"server_name":"proxy.invalid"}}`, version)))
	var err error
	root["outbounds"], err = stdjson.Marshal(outbounds)
	if err != nil {
		t.Fatal(err)
	}
	// The selected named client traverses the same formerly-null H1 helper.
	root["http_clients"] = stdjson.RawMessage(`[{"tag":"fetch","version":1,"detour":"a"}]`)
	encoded, err := stdjson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestRuntimeHTTPTLSExplicitVersionPreservesInitialGraphCapabilities(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "http-version.test"), nil)
			protocolHTTP.RegisterOutbound(service.FromContext[adapter.OutboundRegistry](f.ctx).(*outbound.Registry))
			content := runtimeHTTPVersionEncodingConfig(t, version)
			if err := json.UnmarshalContext(f.ctx, content, &options.Options); err != nil {
				t.Fatal(err)
			}
			if problems := runtimeInitialEligibilityErrors(f.ctx, options); len(problems) != 0 {
				t.Fatalf("valid HTTP-TLS version lost the initial graph: %+v", problems)
			}
			runtimeResourceNew(t, f, options)
			before := f.box.RuntimeCapabilities()
			if before.Enabled || before.Identity.Incarnation == "" {
				t.Fatal("unpublished graph claimed readiness or lost incarnation")
			}
			f.start(t)
			capability := f.box.RuntimeCapabilities()
			if !capability.Enabled || capability.Identity.Revision != 1 || capability.Identity.Incarnation != before.Identity.Incarnation {
				t.Fatalf("HTTP-TLS version disabled actual started graph: %+v", capability)
			}
			if capability.ImplementationManifestDigest == "" {
				t.Fatal("actual runtime manifest missing")
			}
			for _, field := range capability.Fields {
				if field.Path == "runtime.instance" && field.Variant == "INITIAL_CONFIG_ENCODING_FAILED" {
					t.Fatal("H1 variant remained unencodable")
				}
			}
			f.box.runtime.access.Lock()
			canonical := append([]byte(nil), f.box.runtime.canonical...)
			f.box.runtime.access.Unlock()
			var decoded option.Options
			if err := json.UnmarshalContext(f.ctx, canonical, &decoded); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, item := range decoded.Outbounds {
				if item.Tag == "http-tls" {
					found = true
					if actual := item.Options.(*option.HTTPOutboundOptions).Version; actual != version {
						t.Fatalf("HTTP-TLS version silently changed: %d -> %d", version, actual)
					}
				}
			}
			if !found || len(decoded.HTTPClients) != 1 || decoded.HTTPClients[0].Version != 1 {
				t.Fatal("canonical snapshot lost explicit HTTP fields")
			}
			plan, _ := f.plan(t, content)
			if !plan.Applicable || !plan.NoOp {
				t.Fatalf("typed canonical roundtrip stopped being a no-op: %+v", plan)
			}
			invalid, err := f.box.planRuntimeConfig(context.Background(), "actor-a", f.identity(), runtimeHTTPVersionEncodingConfig(t, 4))
			if err != nil || invalid.Applicable || len(invalid.Errors) != 1 || invalid.Errors[0].Code != "INVALID_CONFIG" {
				t.Fatalf("invalid HTTP version bypassed schema gate: %+v %v", invalid, err)
			}
		})
	}
}
