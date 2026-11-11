package box

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/route"
)

// Existing legacy consumers keep their original provisioned-resource surface.
func runtimePlatformRequirementsAvailable(have, need route.RuntimeRequirements) bool {
	if need.Process && !have.Process && !runtimeCanPrepareProcessSearcher() || need.Neighbor && !have.Neighbor || need.WIFI && !have.WIFI {
		return false
	}
	files := make(map[string]bool, len(have.DHCPLeaseFiles))
	for _, path := range have.DHCPLeaseFiles {
		files[path] = true
	}
	for _, path := range need.DHCPLeaseFiles {
		if !files[path] {
			return false
		}
	}
	return true
}

func runtimePlatformRequirementsAvailableForPolicy(ctx context.Context, have, need route.RuntimeRequirements, policy RuntimeClientImpactPolicyVersion) bool {
	if policy == RuntimeClientImpactPolicyExplicit {
		return route.RuntimePlatformPreparationAvailable(ctx, have, need)
	}
	return runtimePlatformRequirementsAvailable(have, need)
}

func runtimeCanPrepareProcessSearcher() bool {
	return C.IsWindows || C.IsLinux && !C.IsAndroid || C.IsDarwin && !C.IsIos
}
