package box

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// Materialize existing first-entry default selection before sorting dependency
// nodes. Source canonical bytes remain unchanged; only this detached graph copy
// receives explicit lookup tags and the existing direct/local fallback nodes.
// Those nodes enter the same dependency/cleanup inventory as explicit members.
func runtimeResolveGraphDefaults(options option.Options) option.Options {
	var routeOptions option.RouteOptions
	if options.Route != nil {
		routeOptions = *options.Route
	}
	options.Route = &routeOptions
	if routeOptions.Final == "" && len(options.Outbounds) == 0 {
		options.Outbounds = []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}}
	}
	if routeOptions.Final == "" && len(options.Outbounds) > 0 {
		routeOptions.Final = options.Outbounds[0].Tag
		if routeOptions.Final == "" {
			routeOptions.Final = "0"
		}
	}
	if options.DNS == nil {
		options.DNS = &option.DNSOptions{}
	}
	if options.DNS != nil {
		dnsOptions := *options.DNS
		if dnsOptions.Final == "" && len(dnsOptions.Servers) == 0 {
			server := option.DNSServerOptions{}
			server.Type = C.DNSTypeLocal
			server.Tag = "local"
			server.Options = &option.LocalDNSServerOptions{}
			dnsOptions.Servers = []option.DNSServerOptions{server}
		}
		options.DNS = &dnsOptions
		if dnsOptions.Final == "" && len(dnsOptions.Servers) > 0 {
			dnsOptions.Final = dnsOptions.Servers[0].Tag
			if dnsOptions.Final == "" {
				dnsOptions.Final = "0"
			}
		}
	}
	return options
}
