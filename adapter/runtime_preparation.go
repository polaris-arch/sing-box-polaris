package adapter

import "context"

type runtimePreparationKey struct{}

// ContextWithRuntimePreparation marks privately staged constructors. It never
// grants publication authority; each producer still needs explicit activation.
func ContextWithRuntimePreparation(ctx context.Context) context.Context {
	return context.WithValue(ctx, runtimePreparationKey{}, true)
}
func IsRuntimePreparation(ctx context.Context) bool {
	prepared, _ := ctx.Value(runtimePreparationKey{}).(bool)
	return prepared
}
