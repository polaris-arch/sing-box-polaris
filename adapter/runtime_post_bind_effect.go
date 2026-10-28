package adapter

import (
	"context"
	"errors"
)

// RuntimePostBindEffect owns external registration/control work that needs its
// actual private socket. Conflict keys are immutable physical/remote identities.
// Suspend must prove absence and join callbacks; an uncertain outcome is an
// error, never permission to restore another registration using the same key.
// All methods execute outside publication guards. Activate only opens an already
// prepared local gate and must not perform registration or user callbacks.
type RuntimePostBindEffect interface {
	RuntimeConflictKeys() []string
	StageRuntime(context.Context) error
	SuspendRuntime(context.Context) error
	RestoreRuntime(context.Context) error
	RuntimeExternalEffects() bool
	RuntimeActivate()
	RuntimeStop()
}
type runtimePostBindRegistrationKey struct{}

func ContextWithRuntimePostBindEffectRegistration(ctx context.Context, register func(RuntimePostBindEffect) error) context.Context {
	return context.WithValue(ctx, runtimePostBindRegistrationKey{}, register)
}

func RegisterRuntimePostBindEffect(ctx context.Context, effect RuntimePostBindEffect) error {
	register, _ := ctx.Value(runtimePostBindRegistrationKey{}).(func(RuntimePostBindEffect) error)
	if register == nil {
		return errors.New("runtime post-bind effect has no preparing owner")
	}
	return register(effect)
}
