package box

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stdjson "encoding/json"
	"runtime"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Save constructor-time closure identities, including actual host inputs.
// Recomputing both sides against today's host would conceal external drift.
func runtimeTunDependencySignatures(ctx context.Context, options option.Options) (map[string]string, error) {
	nodes, configs, err := runtimeConfigNodes(ctx, runtimeResolveGraphDefaults(options))
	if err != nil {
		return nil, err
	}
	cohorts, err := runtimeCohorts(nodes)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(cohorts))
	result := make(map[string]string)
	for index, cohort := range cohorts {
		hash := sha256.New()
		runtimeHashField(hash, cohort.fingerprint)
		for _, dependency := range cohort.dependencies {
			runtimeHashField(hash, hashes[dependency])
		}
		hashes[index] = hex.EncodeToString(hash.Sum(nil))
		for _, name := range cohort.members {
			config := configs[name]
			if config.inbound != nil && config.inbound.Type == C.TypeTun {
				result[name] = hashes[index]
			}
		}
	}
	return result, nil
}

func runtimeTunDependencyChanges(before, after map[string]string) bool {
	if len(before) != len(after) {
		return true
	}
	for name, identity := range before {
		if after[name] != identity {
			return true
		}
	}
	return false
}

// Mask only classified client TUN fields. Never recapture both old and new
// physical closures against today's host: that would hide external drift.
func runtimeClientTunDependencyProblems(ctx context.Context, before, after option.Options, captured map[string]string, policy uint32) []RuntimePlanError {
	problem := []RuntimePlanError{{Code: "RESTART_REQUIRED", Path: "inbounds", DependencyPath: []string{"tun.physical_dependencies"}, Message: "TUN replacement requires a recognized client shape and unchanged captured physical dependencies"}}
	if policy != 1 {
		return problem
	}

	platform := service.FromContext[adapter.PlatformInterface](ctx)
	nativeRequired := runtime.GOOS == "android" || runtime.GOOS == "ios" || platform != nil && (platform.UsePlatformInterface() || platform.UnderNetworkExtension())
	if nativeRequired {
		bridge, ok := platform.(adapter.RuntimeTunPlatform)
		if !ok || bridge.RuntimeTunVersion() != 1 {
			return []RuntimePlanError{{Code: "RESTART_REQUIRED", Path: "inbounds", DependencyPath: []string{"tun.native_fd_settings_owner"}, Message: "native TUN FD/settings migration requires an actually registered V1 original provider owner"}}
		}
	}

	encode := func(options option.Options) stdjson.RawMessage {
		value, err := json.MarshalContext(ctx, options)
		if err != nil {
			return nil
		}
		var root map[string]stdjson.RawMessage
		if stdjson.Unmarshal(value, &root) != nil {
			return nil
		}
		return root["inbounds"]
	}
	if !runtimeClientInboundChanges(encode(before), encode(after), policy) {
		return problem
	}
	masked := after
	masked.Inbounds = append([]option.Inbound(nil), after.Inbounds...)
	old := make(map[string]option.Inbound)
	for _, item := range before.Inbounds {
		if item.Type == C.TypeTun {
			old[item.Tag] = item
		}
	}
	for index, item := range masked.Inbounds {
		if item.Type == C.TypeTun {
			previous, ok := old[item.Tag]
			if !ok {
				return problem
			}
			masked.Inbounds[index] = previous
			delete(old, item.Tag)
		}
	}
	if len(old) != 0 {
		return problem
	}
	identities, err := runtimeTunDependencySignatures(ctx, masked)
	if err != nil || runtimeTunDependencyChanges(captured, identities) {
		return problem
	}
	return nil
}

// Repeat the exact candidate closure after physical staging and before graph
// publication. Plan/constructor observations cannot authorize later host drift.
// Cancellation is observed without using a request context as a service registry.
func (s *Box) validateRuntimeTunPublication(ctx context.Context, prepared *preparedRuntimeGraph) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(prepared.tunDependencies) == 0 {
		return nil
	}
	current, err := runtimeTunDependencySignatures(s.runtime.ctx, prepared.options)
	if err != nil || runtimeTunDependencyChanges(prepared.tunDependencies, current) {
		return &runtimeEndpointRestartRequiredError{detail: RuntimePlanError{Code: "RESTART_REQUIRED", Path: "inbounds", DependencyPath: []string{"tun.physical_dependencies"}, Message: "captured TUN physical inputs changed before publication; candidate not published"}}
	}
	return nil
}
