package box

import (
	"context"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// Named outbound interface policy is graph-private, but accepting an absent or
// down interface would defer failure until after publication. Consult the live
// monitor inventory without invoking an Update/callback from the planner.
func runtimeValidateBoundInterfaces(ctx context.Context, options option.Options) []RuntimePlanError {
	manager := service.FromContext[adapter.NetworkManager](ctx)
	present := make(map[string]bool)
	if manager != nil && manager.InterfaceFinder() != nil {
		for _, device := range manager.InterfaceFinder().Interfaces() {
			present[device.Name] = device.Flags&net.FlagUp != 0
		}
	}
	var problems []RuntimePlanError
	check := func(name, path string) {
		if name != "" && !present[name] {
			problems = append(problems, RuntimePlanError{Code: "INTERFACE_UNAVAILABLE", Path: path, Message: "requested outbound interface is absent or down; current configuration retained"})
		}
	}
	if options.Route != nil {
		check(options.Route.DefaultInterface, "route.default_interface")
	}
	for index, node := range options.Outbounds {
		if value, ok := node.Options.(option.DialerOptionsWrapper); ok {
			check(value.TakeDialerOptions().BindInterface, fmt.Sprintf("outbounds[%d].bind_interface", index))
		}
	}
	for index, node := range options.Endpoints {
		if value, ok := node.Options.(option.DialerOptionsWrapper); ok {
			check(value.TakeDialerOptions().BindInterface, fmt.Sprintf("endpoints[%d].bind_interface", index))
		}
	}
	if options.DNS != nil {
		for index, node := range options.DNS.Servers {
			if value, ok := node.Options.(option.DialerOptionsWrapper); ok {
				check(value.TakeDialerOptions().BindInterface, fmt.Sprintf("dns.servers[%d].bind_interface", index))
			}
		}
	}
	return problems
}
