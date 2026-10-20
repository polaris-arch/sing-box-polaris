package adapter

import "context"

type RuntimeControl interface {
	SelectRuntimeOutbound(expected RuntimeResourceID, group, selected string) bool
}
type runtimeControlKey struct{}
func ContextWithRuntimeControl(ctx context.Context, control RuntimeControl) context.Context {
	return context.WithValue(ctx, runtimeControlKey{}, control)
}
func RuntimeControlFromContext(ctx context.Context) (RuntimeControl, bool) {
	control, ok := ctx.Value(runtimeControlKey{}).(RuntimeControl)
	return control, ok && control != nil
}

// RuntimeModeControl shares the same manual-control revision as selectors.
type RuntimeModeControl interface { SetRuntimeClashMode(string) bool }
