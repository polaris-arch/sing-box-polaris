//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-tun"
)

// The prematch generation is part of original flow ownership. Native copies
// must retain it through the existing verdict protocol, never choose publication
// again when the same flow reaches a later inbound/DNS handoff.
type runtimeBindingFlow struct {
	mu       sync.Mutex
	inner    tun.FlowOwnership
	binding  *runtimeEndpointBinding
	owned    context.Context
	release  func()
	released bool
}

func (f *runtimeBindingFlow) Retain() (tun.FlowOwnership, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released {
		return nil, errors.New("tailscale flow binding already released")
	}
	owned, release, err := f.binding.acquire(f.owned)
	if err != nil {
		return nil, err
	}
	var inner tun.FlowOwnership
	if f.inner != nil {
		inner, err = f.inner.Retain()
		if err != nil {
			release()
			return nil, err
		}
	}
	return &runtimeBindingFlow{inner: inner, binding: f.binding, owned: owned, release: release}, nil
}

func (f *runtimeBindingFlow) BindContext(ctx context.Context) context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inner != nil {
		ctx = f.inner.BindContext(ctx)
	}
	// Even after Release, keep the exact (now invalid) capability in the context.
	// Admission must fail instead of silently switching to a current root.
	return context.WithValue(ctx, runtimeBindingContextKey{}, f.owned.Value(runtimeBindingContextKey{}))
}

func (f *runtimeBindingFlow) RetainPort(port tun.Port) (tun.PortOwnership, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.released || f.inner == nil {
		return nil, errors.New("tailscale verdict has no retained port authority")
	}
	return f.inner.RetainPort(port)
}

func (f *runtimeBindingFlow) Release() {
	f.mu.Lock()
	if f.released {
		f.mu.Unlock()
		return
	}
	f.released = true
	inner, release := f.inner, f.release
	f.mu.Unlock()
	if inner != nil {
		inner.Release()
	}
	release()
}
