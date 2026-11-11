package box

import (
	"context"

	"github.com/sagernet/sing-box/option"
)

type runtimeLogDisableColorKey struct{}

// ContextWithRuntimeLogDisableColor preserves an explicit host CLI override
// across public Plan/Apply. It grants no new output path or logger capability.
func ContextWithRuntimeLogDisableColor(ctx context.Context) context.Context {
	return context.WithValue(ctx, runtimeLogDisableColorKey{}, true)
}

func runtimeResolveLogOverrides(ctx context.Context, options *option.Options) {
	forced, _ := ctx.Value(runtimeLogDisableColorKey{}).(bool)
	if !forced {
		return
	}
	var value option.LogOptions
	if options.Log != nil {
		value = *options.Log
	}
	value.DisableColor = true
	options.Log = &value
}
