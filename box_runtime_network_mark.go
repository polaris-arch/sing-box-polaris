package box

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/service"
)

func runtimeAutoRedirectMark(ctx context.Context, options option.Options) (uint32, error) {
	platform := service.FromContext[adapter.PlatformInterface](ctx)
	platformRedirect := platform != nil && platform.UsePlatformAutoRedirect()
	var mark uint32
	for _, input := range options.Inbounds {
		value, ok := input.Options.(*option.TunInboundOptions)
		if !ok || !value.AutoRedirect || value.NetNs != "" || platformRedirect {
			continue
		}
		if mark != 0 {
			return 0, errors.New("only one auto-redirect can be configured")
		}
		declaration := tun.Options{AutoRedirectOutputMark: uint32(value.AutoRedirectOutputMark)}
		mark = declaration.AutoRedirectOutputMarkOrDefault()
	}
	return mark, nil
}
