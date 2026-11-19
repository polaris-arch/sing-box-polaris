package adapter

import (
	"context"
	"errors"

	"github.com/sagernet/sing/service"
)

// The logical endpoint owns these actual physical-child completion signals.
// Observers may time out but cannot close either signal or overwrite a sticky
// result. Snapshot callbacks must be safe during partial construction.
type RuntimeTailscaleChildRequest struct {
	ResourceID                             RuntimeResourceID
	Generation                             uint64
	Tag, StateDirectory, TaildropDirectory string
	ConstructionDone, CloseDone            <-chan struct{}
	ConstructionResult                     func() error
	CloseResult                            func() error
	StoreScopes                            func() []TailscaleStoreNode
	DirectoryScopes                        func() []TailscaleDirectoryNode
	NativeWriter                           *RuntimeTailscaleDirectories
}

// RuntimeTailscaleDirectories are the configured paths resolved by the actual
// constructor. The native host resolves aliases in its own ownership domain.
type RuntimeTailscaleDirectories struct {
	State, Taildrop string
}

type RuntimeTailscaleWriterScope struct {
	ResourceID  RuntimeResourceID
	Generation  uint64
	Binding     TailscaleStoreRunBinding
	Tag         string
	Directories RuntimeTailscaleDirectories
}

// RuntimeTailscaleWriterPlatform is optional. Platforms requiring this fence
// may enable a warm writer only via their original native command owner.
type RuntimeTailscaleWriterPlatform interface {
	RequiresRuntimeTailscaleWriter() bool
	ValidateRuntimeTailscaleWriter(tag string, directories RuntimeTailscaleDirectories) bool
	ClaimRuntimeTailscaleWriter(scope RuntimeTailscaleWriterScope) (bool, error)
	ReleaseRuntimeTailscaleWriter(scope RuntimeTailscaleWriterScope, acquired bool) error
}

func RuntimeTailscaleWriterFromContext(ctx context.Context) RuntimeTailscaleWriterPlatform {
	platform, _ := service.FromContext[PlatformInterface](ctx).(RuntimeTailscaleWriterPlatform)
	if platform == nil || !platform.RequiresRuntimeTailscaleWriter() {
		return nil
	}
	return platform
}

type RuntimeTailscaleChildRegistration interface {
	Context() context.Context
	Prepare(context.Context) error
	Constructed() error
	Abort() error
}

// RuntimeTailscaleNativeClose observes completion of the native writer host
// after the physical owner's own CloseDone. The wait is bounded and sticky.
type RuntimeTailscaleNativeClose interface {
	WaitOriginalNativeClose() error
}
type (
	RuntimeTailscaleChildRegistrar    func(context.Context, RuntimeTailscaleChildRequest) (RuntimeTailscaleChildRegistration, error)
	runtimeTailscaleChildRegistrarKey struct{}
	runtimeTailscaleChildCapacityKey  struct{}
	runtimeTailscaleNativeWriterKey   struct{}
)

func ContextWithRuntimeTailscaleChildRegistrar(ctx context.Context, registrar RuntimeTailscaleChildRegistrar) context.Context {
	return context.WithValue(ctx, runtimeTailscaleChildRegistrarKey{}, registrar)
}

func ContextWithRuntimeTailscaleChildCapacity(ctx context.Context, check func() bool) context.Context {
	return context.WithValue(ctx, runtimeTailscaleChildCapacityKey{}, check)
}

func RuntimeTailscaleChildHasCapacity(ctx context.Context) bool {
	check, _ := ctx.Value(runtimeTailscaleChildCapacityKey{}).(func() bool)
	return check != nil && check()
}

func ContextWithRuntimeTailscaleNativeWriter(ctx context.Context) context.Context {
	return context.WithValue(ctx, runtimeTailscaleNativeWriterKey{}, true)
}

func RuntimeTailscaleNativeWriterRequired(ctx context.Context) bool {
	required, _ := ctx.Value(runtimeTailscaleNativeWriterKey{}).(bool)
	return required
}

func RegisterRuntimeTailscaleChild(ctx context.Context, request RuntimeTailscaleChildRequest) (RuntimeTailscaleChildRegistration, error) {
	registrar, _ := ctx.Value(runtimeTailscaleChildRegistrarKey{}).(RuntimeTailscaleChildRegistrar)
	if registrar == nil {
		return nil, errors.New("runtime Tailscale child registration unavailable")
	}
	if request.ResourceID == (RuntimeResourceID{}) || request.Generation == 0 || request.Tag == "" || request.ConstructionDone == nil || request.CloseDone == nil || request.ConstructionResult == nil || request.CloseResult == nil || request.StoreScopes == nil || request.DirectoryScopes == nil {
		return nil, errors.New("incomplete original Tailscale child evidence")
	}
	source, ok := RuntimeResourceSourceFromContext(ctx)
	if !ok || source.ID() != request.ResourceID {
		return nil, errors.New("tailscale child does not match constructor owner")
	}
	return registrar(ctx, request)
}

type runtimeTailscaleConfigurationKey struct{}

// Whole effective configuration bytes are captured before any child is born.
// A child cannot substitute a caller-supplied digest or select a newer graph.
func ContextWithRuntimeTailscaleConfiguration(ctx context.Context, canonical []byte) context.Context {
	return context.WithValue(ctx, runtimeTailscaleConfigurationKey{}, append([]byte(nil), canonical...))
}

func RuntimeTailscaleConfiguration(ctx context.Context) ([]byte, bool) {
	canonical, ok := ctx.Value(runtimeTailscaleConfigurationKey{}).([]byte)
	return append([]byte(nil), canonical...), ok && len(canonical) > 0
}

type runtimeTailscalePlanDigestKey struct{}

// The Plan digest identifies the exact accepted canonical configuration. It is
// distinct from construction options that already embed frozen source data.
func ContextWithRuntimeTailscalePlanDigest(ctx context.Context, digest string) context.Context {
	return context.WithValue(ctx, runtimeTailscalePlanDigestKey{}, digest)
}

func RuntimeTailscalePlanDigest(ctx context.Context) (string, bool) {
	digest, _ := ctx.Value(runtimeTailscalePlanDigestKey{}).(string)
	return digest, digest != ""
}

// The registration context still identifies the original logical birth and
// immutable effective configuration. A shared physical child may instead retain
// this explicitly supplied Box-stable base, without the first graph's services
// or cancellation. The physical owner must hold its own stable resource lease.
type runtimeTailscaleChildBaseKey struct{}

func ContextWithRuntimeTailscaleChildBase(registration context.Context, physicalBase context.Context) context.Context {
	if physicalBase == nil {
		return registration
	}
	return context.WithValue(registration, runtimeTailscaleChildBaseKey{}, physicalBase)
}

func RuntimeTailscaleChildBase(registration context.Context) (context.Context, bool) {
	base, ok := registration.Value(runtimeTailscaleChildBaseKey{}).(context.Context)
	return base, ok && base != nil
}
