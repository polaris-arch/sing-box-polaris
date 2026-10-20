package route

import (
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

// BuildNetworkOptions projects owned default values without constructing monitors
// or looking up DNS policies, which are initialized later during normal startup.
func BuildNetworkOptions(options option.RouteOptions) (adapter.NetworkOptions, error) {
	resolver := common.PtrValueOrDefault(options.DefaultDomainResolver)
	if err := resolver.Validate(); err != nil {
		return adapter.NetworkOptions{}, err
	}
	if options.AutoDetectInterface && !(C.IsLinux || C.IsDarwin || C.IsWindows) {
		return adapter.NetworkOptions{}, E.New("`auto_detect_interface` is only supported on Linux, Windows and macOS")
	} else if options.OverrideAndroidVPN && !C.IsAndroid {
		return adapter.NetworkOptions{}, E.New("`override_android_vpn` is only supported on Android")
	} else if options.DefaultInterface != "" && !(C.IsLinux || C.IsDarwin || C.IsWindows) {
		return adapter.NetworkOptions{}, E.New("`default_interface` is only supported on Linux, Windows and macOS")
	} else if options.DefaultMark != 0 && !C.IsLinux {
		return adapter.NetworkOptions{}, E.New("`default_mark` is only supported on linux")
	}
	if options.DefaultNetworkStrategy != nil {
		if options.DefaultInterface != "" {
			return adapter.NetworkOptions{}, E.New("`default_network_strategy` is conflict with `default_interface`")
		}
		if !options.AutoDetectInterface {
			return adapter.NetworkOptions{}, E.New("`auto_detect_interface` is required by `default_network_strategy`")
		}
	}
	return cloneNetworkOptions(adapter.NetworkOptions{
		BindInterface: options.DefaultInterface,
		RoutingMark: uint32(options.DefaultMark),
		DomainResolver: resolver.Server,
		DomainResolveOptions: adapter.DNSQueryOptions{
			UseRules: resolver.Mode == option.DomainResolverModeRules,
			Policy: common.PtrValueOrDefault(resolver.Policy),
			Strategy: C.DomainStrategy(resolver.Strategy),
			Timeout: time.Duration(resolver.Timeout),
			DisableCache: resolver.DisableCache,
			DisableOptimisticCache: resolver.DisableOptimisticCache,
			RewriteTTL: resolver.RewriteTTL,
			ClientSubnet: resolver.ClientSubnet.Build(netip.Prefix{}),
		},
		NetworkStrategy: (*C.NetworkStrategy)(options.DefaultNetworkStrategy),
		NetworkType: common.Map(options.DefaultNetworkType, option.InterfaceType.Build),
		FallbackNetworkType: common.Map(options.DefaultFallbackNetworkType, option.InterfaceType.Build),
		FallbackDelay: time.Duration(options.DefaultFallbackDelay),
	}), nil
}

func cloneNetworkOptions(options adapter.NetworkOptions) adapter.NetworkOptions {
	if options.NetworkStrategy != nil {
		strategy := *options.NetworkStrategy
		options.NetworkStrategy = &strategy
	}
	if options.DomainResolveOptions.RewriteTTL != nil {
		ttl := *options.DomainResolveOptions.RewriteTTL
		options.DomainResolveOptions.RewriteTTL = &ttl
	}
	if options.NetworkType != nil {
		options.NetworkType = append([]C.InterfaceType{}, options.NetworkType...)
	}
	if options.FallbackNetworkType != nil {
		options.FallbackNetworkType = append([]C.InterfaceType{}, options.FallbackNetworkType...)
	}
	return options
}
