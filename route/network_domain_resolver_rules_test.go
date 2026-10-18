package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// A host stub keeps construction free of native monitors and network sockets.
type rulesNetworkTestPlatform struct{ adapter.PlatformInterface }

func (rulesNetworkTestPlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (rulesNetworkTestPlatform) CreateDefaultInterfaceMonitor(logger logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}

func TestDefaultDomainResolverRulesProjection(t *testing.T) {
	ctx := service.ContextWith[adapter.PlatformInterface](context.Background(), rulesNetworkTestPlatform{})
	resolver := &option.DomainResolveOptions{Mode: option.DomainResolverModeRules, Strategy: option.DomainStrategy(C.DomainStrategyPreferIPv4), Timeout: badoption.Duration(2 * time.Second), DisableCache: true}
	manager, err := NewNetworkManager(ctx, log.NewNOPFactory().Logger(), option.RouteOptions{DefaultDomainResolver: resolver}, option.DNSOptions{})
	require.NoError(t, err)
	options := manager.DefaultOptions()
	require.Empty(t, options.DomainResolver)
	require.True(t, options.DomainResolveOptions.UseRules)
	require.Equal(t, C.DomainStrategyPreferIPv4, options.DomainResolveOptions.Strategy)
	require.Equal(t, 2*time.Second, options.DomainResolveOptions.Timeout)
	require.True(t, options.DomainResolveOptions.DisableCache)
	_, err = NewNetworkManager(ctx, log.NewNOPFactory().Logger(), option.RouteOptions{DefaultDomainResolver: &option.DomainResolveOptions{Mode: option.DomainResolverModeRules, Server: "bootstrap"}}, option.DNSOptions{})
	require.ErrorContains(t, err, "conflicts with rules mode")
}
