//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service/filemanager"
)

// RuntimeSetPhysicalBase supplies the existing Box-stable owner. No logical
// graph registry, cancellation or policy source may be used as this base.
// Original birth provenance is registered separately through the logical ctx.
func (t *Endpoint) RuntimeSetPhysicalBase(ctx context.Context, source adapter.RuntimeResourceSource, logger log.ContextLogger) error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	if ctx == nil || source == nil || logger == nil {
		return errors.New("incomplete Tailscale physical base")
	}
	if source.ID() == t.runtime.source.ID() {
		return errors.New("tailscale physical base cannot retain its logical owner")
	}
	r := t.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.physical != nil || r.reserved != nil {
		return errors.New("tailscale physical base supplied after reservation")
	}
	r.baseContext = ctx
	r.baseSource = source
	r.baseLogger = logger
	return nil
}

// RuntimeCanSharePhysical deliberately excludes only replaceable dialer policy.
// Every identity, auth, directory, preference, device and feature option is
// compared, including newly added fields. Default/expanded directory spelling
// follows the captured original constructor's existing normalization.
func (t *Endpoint) RuntimeCanSharePhysical(tag string, options option.TailscaleEndpointOptions) bool {
	if t.runtime == nil || tag == "" {
		return false
	}
	options.StateDirectory = os.ExpandEnv(options.StateDirectory)
	options.TaildropDirectory = os.ExpandEnv(options.TaildropDirectory)
	r := t.runtime
	r.mu.Lock()
	old := cloneRuntimeOptions(r.options)
	p := r.physical
	closing := r.closing
	r.mu.Unlock()
	old.DialerOptions = option.DialerOptions{}
	options.DialerOptions = option.DialerOptions{}
	if closing || p == nil || !reflect.DeepEqual(old, options) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closing && p.child != nil
}

// Attach is linearized with last detach. A prepared private candidate counts
// immediately; publishing does not create a new native identity or census run.
func (p *runtimeEndpointPhysical) attach(b *runtimeEndpointBinding) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return net.ErrClosed
	}
	if _, exists := p.attachments[b]; exists {
		return errors.New("duplicate Tailscale physical attachment")
	}
	b.physical = p
	p.attachments[b] = struct{}{}
	if p.child == nil && p.bootstrap == nil {
		p.bootstrap = b
	}
	return nil
}

func (p *runtimeEndpointPhysical) detach(b *runtimeEndpointBinding) error {
	p.mu.Lock()
	if _, attached := p.attachments[b]; !attached {
		p.mu.Unlock()
		return nil
	}
	delete(p.attachments, b)
	if p.active == b {
		p.active = nil
	}
	if p.bootstrap == b {
		p.bootstrap = nil
	}
	last := len(p.attachments) == 0
	if last {
		p.closing = true
	}
	p.mu.Unlock()
	// Closing and all original waits are outside the attachment mutex. The
	// closing bit cannot be reset: no racing attach can resurrect this owner.
	if last {
		return p.close()
	}
	return nil
}

func (p *runtimeEndpointPhysical) bindingContext(ctx context.Context, ingress bool) (*runtimeEndpointBinding, context.Context, func(), error) {
	if inherited, ok := ctx.Value(runtimeBindingContextKey{}).(*runtimeBindingContinuation); ok {
		if inherited == nil || inherited.binding.physical != p {
			return nil, nil, nil, errors.New("tailscale inherited binding does not match physical owner")
		}
		owned, release, err := inherited.binding.acquire(ctx)
		return inherited.binding, owned, release, err
	}
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return nil, nil, nil, net.ErrClosed
	}
	b := p.active
	if b == nil && !ingress {
		b = p.bootstrap
	}
	if b == nil {
		p.mu.Unlock()
		return nil, nil, nil, net.ErrClosed
	}
	// Admission and pointer selection occur under the same attachment mutex.
	// The call executes only after that mutex has been released.
	owned, release, err := b.acquire(ctx)
	p.mu.Unlock()
	return b, owned, release, err
}

func (t *Endpoint) RuntimeStageSharedPhysical(ctx context.Context, prior *Endpoint) error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	if prior == nil || prior == t || !prior.RuntimeCanSharePhysical(t.Tag(), t.runtime.options) {
		return errors.New("tailscale physical identity is not shareable")
	}
	return t.runtime.run(ctx, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		prior.runtime.mu.Lock()
		p := prior.runtime.physical
		prior.runtime.mu.Unlock()
		if p == nil {
			return net.ErrClosed
		}
		r := t.runtime
		r.mu.Lock()
		existing, reserved := r.physical, r.reserved
		r.mu.Unlock()
		if existing != nil || reserved != nil {
			return errors.New("tailscale shared attachment must precede fresh birth reservation")
		}
		b, err := t.newRuntimeBinding(p)
		if err != nil {
			return err
		}
		if err = p.attach(b); err != nil {
			return errors.Join(err, b.closeAndWait())
		}
		r.mu.Lock()
		r.physical = p
		r.binding = b
		t.queryOptions = b.query
		r.mu.Unlock()
		p.mu.Lock()
		child := p.child
		p.mu.Unlock()
		if child == nil {
			return errors.New("tailscale shared physical child is not constructed")
		}
		// Replay under the same lock as the original reconfiguration callback. A
		// private DNS consumer must have a usable snapshot before publication.
		child.reconfigAccess.Lock()
		if child.routerCfg != nil && child.dnsCfg != nil {
			p.reconfigured(child, child.cfg, child.routerCfg, child.dnsCfg)
		}
		child.reconfigAccess.Unlock()
		r.mu.Lock()
		reconfigErr := r.reconfigErr
		r.mu.Unlock()
		return reconfigErr
	})
}

func (t *Endpoint) runtimeBoundChild(ctx context.Context) (*Endpoint, context.Context, func(), error) {
	child, leave, err := t.runtimeChild(false)
	if err != nil {
		return nil, nil, nil, err
	}
	t.runtime.mu.Lock()
	b := t.runtime.binding
	t.runtime.mu.Unlock()
	if b == nil {
		leave()
		return nil, nil, nil, net.ErrClosed
	}
	owned, release, err := b.acquire(ctx)
	if err != nil {
		leave()
		return nil, nil, nil, err
	}
	owned, cancel := b.physical.joinContext(owned)
	return child, owned, func() { cancel(); release(); leave() }, nil
}

func (t *Endpoint) RuntimePhysicalOptions() option.TailscaleEndpointOptions {
	if t.runtime == nil {
		return option.TailscaleEndpointOptions{}
	}
	t.runtime.mu.Lock()
	defer t.runtime.mu.Unlock()
	return cloneRuntimeOptions(t.runtime.options)
}

// RuntimePhysicalDirectories mirrors constructor default/expansion/base-path
// normalization without acquiring a directory, creating files or authenticating.
// These are logical configured paths, not a private run's mapped storage paths.
func RuntimePhysicalDirectories(ctx context.Context, options option.TailscaleEndpointOptions) (state, taildrop string, err error) {
	state = options.StateDirectory
	if state == "" {
		state = "tailscale"
	}
	taildrop = options.TaildropDirectory
	if taildrop == "" {
		taildrop = "Taildrop"
	}
	state, err = filepath.Abs(filemanager.BasePath(ctx, os.ExpandEnv(state)))
	if err != nil {
		return "", "", err
	}
	taildrop, err = filepath.Abs(filemanager.BasePath(ctx, os.ExpandEnv(taildrop)))
	return
}
