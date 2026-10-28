package adapter

import "context"

type runtimePreparedResourceCheckKey struct{}

// Constructor-private authority for candidate-local mutation. The Box supplies
// an immutable created-allocation set, never a tag lookup or current graph view.
// Reused allocations are absent even when they belong to the same incarnation.
func ContextWithRuntimePreparedResourceCheck(ctx context.Context, check func(RuntimeResourceID) bool) context.Context {
	return context.WithValue(ctx, runtimePreparedResourceCheckKey{}, check)
}

func RuntimeResourcePreparedInContext(ctx context.Context, id RuntimeResourceID) bool {
	check, _ := ctx.Value(runtimePreparedResourceCheckKey{}).(func(RuntimeResourceID) bool)
	return id != (RuntimeResourceID{}) && check != nil && check(id)
}
