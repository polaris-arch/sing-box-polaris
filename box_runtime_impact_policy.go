package box

import "context"

// RuntimeClientImpactPolicyVersion describes the authenticated consumer's
// ability to present and bind impact confirmation. It never attests consent.
type RuntimeClientImpactPolicyVersion uint32

const (
	RuntimeClientImpactPolicyLegacy RuntimeClientImpactPolicyVersion = iota
	RuntimeClientImpactPolicyExplicit
)

func runtimeClientImpactPolicySupported(version RuntimeClientImpactPolicyVersion) bool {
	return version == RuntimeClientImpactPolicyLegacy || version == RuntimeClientImpactPolicyExplicit
}

func runtimeImpactConfirmationRequired(version RuntimeClientImpactPolicyVersion, impacts []RuntimeImpact) bool {
	if version != RuntimeClientImpactPolicyExplicit {
		return false
	}
	for _, impact := range impacts {
		if impact.ReconnectRequired || impact.UpdateClass == "AFFECTED_RECONNECT" {
			return true
		}
	}
	return false
}

// A preparation's policy comes only from its stored, actor-bound Plan. The
// accepted reconnect impact alone must never upgrade a legacy transaction.
type runtimeClientImpactPolicyKey struct{}

func runtimeContextWithClientImpactPolicy(ctx context.Context, policy RuntimeClientImpactPolicyVersion) context.Context {
	return context.WithValue(ctx, runtimeClientImpactPolicyKey{}, policy)
}

func runtimeClientImpactPolicyFromContext(ctx context.Context) RuntimeClientImpactPolicyVersion {
	policy, _ := ctx.Value(runtimeClientImpactPolicyKey{}).(RuntimeClientImpactPolicyVersion)
	return policy
}
