package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// prepareTailscaleDirectoryMapping never rewrites options or the submitted
// profile, so authentication-store binding retains the original config digest.
// Any invalid member downgrades the entire config, not just that endpoint.
func prepareTailscaleDirectoryMapping(ctx context.Context, options option.Options) (context.Context, error) {
	// Shadow any inherited plan. Each instance needs its own whole-config census.
	ctx = adapter.ContextWithTailscaleDirectoryMapping(ctx, nil)
	domain := adapter.TailscaleDirectoryDomainFromContext(ctx)
	if domain == nil {
		return ctx, nil
	}
	if !domain.Active() {
		if domain.Failure() != nil {
			return ctx, domain.FailurePersistenceError()
		}
		return ctx, errors.New("managed directory domain has not completed activation")
	}
	var inputs []adapter.TailscaleDirectoryMappingInput
	for _, endpoint := range options.Endpoints {
		if endpoint.Type != C.TypeTailscale {
			continue
		}
		ts, ok := endpoint.Options.(*option.TailscaleEndpointOptions)
		if !ok || ts == nil || (ts.SSHServer != nil && ts.SSHServer.Enabled) {
			err := domain.Fail(errors.New("Tailscale endpoint cannot be scoped in managed domain"))
			return ctx, err
		}
		inputs = append(inputs, adapter.TailscaleDirectoryMappingInput{StateDirectory: ts.StateDirectory, TaildropDirectory: ts.TaildropDirectory})
	}
	mapping, err := adapter.NewTailscaleDirectoryMapping(domain, inputs)
	if err != nil {
		return ctx, domain.FailurePersistenceError()
	}
	return adapter.ContextWithTailscaleDirectoryMapping(ctx, mapping), nil
}

// guardRawDirectoryNamespace runs before typed option decoding or construction.
// Token scanning visits every decoded string, including duplicate object keys,
// nested unknown options and escaped paths. Inspect the fixed basename as well
// as absolute paths: relative paths from workingPath may select this namespace.
// This is a cooperative-writer guard, not protection from arbitrary code under
// the same OS identity. No string or JSON flag grants managed authority.
func guardRawDirectoryNamespace(ctx context.Context, content string) error {
	domain := adapter.TailscaleDirectoryDomainFromContext(ctx)
	if domain == nil {
		return nil
	}
	if !domain.Activated() {
		return errors.New("managed directory domain is not activated")
	}
	if err := domain.FailurePersistenceError(); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.UseNumber()
	selectsPhysical := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Unknown dialect/shape cannot retain proof. Preserve legacy parsing
			// behavior only after durable revocation has completed.
			return domain.Fail(errors.New("managed configuration namespace scan is incomplete"))
		}
		if value, ok := token.(string); ok && (strings.Contains(strings.ToLower(value), "tailscale-g4-v1") || strings.Contains(strings.ToLower(os.ExpandEnv(value)), "tailscale-g4-v1")) {
			selectsPhysical = true
		}
	}
	if selectsPhysical {
		return domain.Fail(errors.New("raw profile explicitly selects managed physical namespace"))
	}
	return nil
}
