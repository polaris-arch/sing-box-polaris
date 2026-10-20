package adapter

import (
 "context"
 "errors"
)

// RuntimeStagedEffect describes an owned component's non-publication phase.
// Stage and compensation can perform I/O. Neither may run in the graph guard.
// Activation is also outside that guard. Publication itself only swaps memory.
type RuntimeStagedEffect interface {
 StageRuntime(context.Context) error
 CompensateRuntime() error
 RuntimeExternalEffects() bool
 RuntimeActivate()
 RuntimeStop()
}
type runtimeEffectRegistrationKey struct{}
func ContextWithRuntimeEffectRegistration(ctx context.Context, register func(RuntimeStagedEffect)error)context.Context{
 return context.WithValue(ctx,runtimeEffectRegistrationKey{},register)
}
func RegisterRuntimeEffect(ctx context.Context,effect RuntimeStagedEffect)error{
 register,_:=ctx.Value(runtimeEffectRegistrationKey{}).(func(RuntimeStagedEffect)error)
 if register==nil{return errors.New("runtime external effect has no preparing owner")}
 return register(effect)
}
