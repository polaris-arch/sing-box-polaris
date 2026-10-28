package adapter

import "context"

type constructionScopeKey struct{}

// ContextWithConstructionScope returns a context that carries the scope
// owning resources acquired while a box is being constructed.
func ContextWithConstructionScope(ctx context.Context, scope *Scope) context.Context {
	return context.WithValue(ctx, constructionScopeKey{}, scope)
}

// DeferConstructionCleanup registers cleanup for a resource acquired by a
// constructor, so that it is released when the box is closed or when its
// construction fails, even if the component is never started.
//
// If the context carries no construction scope, or the context of the scope
// is done, the cleanup is executed immediately and its result is returned. The
// context of a scope is done once the scope is closed, and also once the
// context the scope was created from is canceled, even though that scope may
// still be closed later.
func DeferConstructionCleanup(ctx context.Context, cleanup func() error) error {
	scope, _ := ctx.Value(constructionScopeKey{}).(*Scope)
	if scope == nil {
		return cleanup()
	}
	scope.access.Lock()
	if scope.ctx.Err() != nil {
		scope.access.Unlock()
		return cleanup()
	}
	scope.cleanups = append(scope.cleanups, cleanup)
	scope.access.Unlock()
	return nil
}
