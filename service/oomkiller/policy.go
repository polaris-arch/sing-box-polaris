package oomkiller

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/memory"
	"github.com/sagernet/sing/service"
)

const (
	DefaultAppleNetworkExtensionMemoryLimit = 50 * 1024 * 1024
	DefaultAppleNetworkExtensionGCPercent   = 25
	AppleNetworkExtensionGoMemoryLimit      = 32 * 1024 * 1024
)

// HostOptions is the process owner's default OOM configuration. Profile JSON
// can declare its own OOM service but cannot set these host options.
type HostOptions struct {
	Enabled             bool
	KillerDisabled      bool
	MemoryLimitOverride uint64
}

type hostOptionsKey struct{}

func ContextWithHostOptions(ctx context.Context, options HostOptions) context.Context {
	return context.WithValue(ctx, hostOptionsKey{}, options)
}

func HostOptionsFromContext(ctx context.Context) (HostOptions, bool) {
	options, ok := ctx.Value(hostOptionsKey{}).(HostOptions)
	return options, ok
}

func (o HostOptions) ServiceOptions() *option.OOMKillerServiceOptions {
	return &option.OOMKillerServiceOptions{KillerDisabled: o.KillerDisabled, MemoryLimitOverride: o.MemoryLimitOverride}
}

type policyMode uint8

const (
	policyModeNone policyMode = iota
	policyModeMemoryLimit
	policyModeAvailable
	policyModeNetworkExtension
)

func (m policyMode) hasTimerMode() bool {
	return m != policyModeNone
}

func (m policyMode) String() string {
	switch m {
	case policyModeMemoryLimit:
		return "memory_limit"
	case policyModeAvailable:
		return "available"
	case policyModeNetworkExtension:
		return "network_extension"
	default:
		return "none"
	}
}

func InAppleNetworkExtension(ctx context.Context) bool {
	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	return C.IsIos && platformInterface != nil && platformInterface.UnderNetworkExtension()
}

func resolvePolicyMode(ctx context.Context, options option.OOMKillerServiceOptions) (uint64, policyMode) {
	if InAppleNetworkExtension(ctx) {
		return DefaultAppleNetworkExtensionMemoryLimit, policyModeNetworkExtension
	}
	if options.MemoryLimitOverride > 0 {
		return options.MemoryLimitOverride, policyModeMemoryLimit
	}
	if options.MemoryLimit != nil {
		memoryLimit := options.MemoryLimit.Value()
		if memoryLimit > 0 {
			return memoryLimit, policyModeMemoryLimit
		}
	}
	if memory.AvailableAvailable() {
		return 0, policyModeAvailable
	}
	return 0, policyModeNone
}
