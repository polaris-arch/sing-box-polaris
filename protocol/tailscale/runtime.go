//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	runtimeTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

type (
	runtimePhysicalEndpointKey struct{}
	runtimeUnusedChild         struct{}
)

func (runtimeUnusedChild) Error() string                       { return "Tailscale child reservation was never acquired" }
func (runtimeUnusedChild) RuntimeTailscaleNoAcquisition() bool { return true }

type runtimeEndpointPhysical struct {
	mu               sync.Mutex
	child            *Endpoint
	directory        *directoryOwner
	store            *guardedStateStore
	ctx              context.Context
	scope            *adapter.Scope
	source           adapter.RuntimeResourceSource
	callbacks        *outbound.RuntimeIOFence
	carriers         *outbound.RuntimeIOFenceSet
	begin            func(context.Context) (context.Context, func(), error)
	registration     adapter.RuntimeTailscaleChildRegistration
	reservationErr   error
	cancel           context.CancelFunc
	attachments      map[*runtimeEndpointBinding]struct{}
	active           *runtimeEndpointBinding
	bootstrap        *runtimeEndpointBinding
	closing          bool
	baseLease        adapter.RuntimeResourceLease
	returns          runtimeEndpointReturn
	generation       uint64
	constructionOnce sync.Once
	constructionDone chan struct{}
	constructionErr  error
	acquisition      bool
	closeOnce        sync.Once
	closeDone        chan struct{}
	closeErr         error
}

func (p *runtimeEndpointPhysical) constructed(err error) {
	p.constructionOnce.Do(func() { p.mu.Lock(); p.constructionErr = err; p.mu.Unlock(); close(p.constructionDone) })
}

func (p *runtimeEndpointPhysical) constructionResult() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.constructionErr
}

func (p *runtimeEndpointPhysical) closeResult() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeErr
}

func (p *runtimeEndpointPhysical) observe(child *Endpoint, directory *directoryOwner, store *guardedStateStore) {
	p.mu.Lock()
	if child != nil {
		p.child = child
	}
	if directory != nil {
		p.directory = directory
	}
	if store != nil {
		p.store = store
	}
	p.mu.Unlock()
}

func (p *runtimeEndpointPhysical) storeScopes() []adapter.TailscaleStoreNode {
	p.mu.Lock()
	store := p.store
	p.mu.Unlock()
	if store == nil {
		return nil
	}
	select {
	case <-p.closeDone:
		return []adapter.TailscaleStoreNode{store.terminal}
	default:
		return []adapter.TailscaleStoreNode{store.node}
	}
}

func (p *runtimeEndpointPhysical) directoryScopes() []adapter.TailscaleDirectoryNode {
	p.mu.Lock()
	directory := p.directory
	p.mu.Unlock()
	if directory == nil {
		return nil
	}
	return []adapter.TailscaleDirectoryNode{directory.snapshot()}
}

func (p *runtimeEndpointPhysical) close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closing = true
		p.closeErr = runtimeTLS.NewRuntimeCleanupError(errors.New("Tailscale physical close did not return"))
		child := p.child
		acquisition := p.acquisition
		p.mu.Unlock()
		defer close(p.closeDone)
		p.cancel()
		_ = p.callbacks.Close()
		p.carriers.Stop()
		if !acquisition {
			p.constructed(runtimeUnusedChild{})
		}
		var childErr error
		if child != nil && child.directory != nil {
			// Capture Store evidence while the original localBackend is still present,
			// then start native shutdown. Scope cleanup closes SSH/session owners before
			// observing directory retirement; no artificial five-second pre-SSH wait.
			if child.stateStore != nil {
				childErr = child.retireStateStore()
			}
			child.beginDirectoryRetirement()
		}
		scopeErr := p.scope.Close()
		if child != nil {
			if child.directory != nil {
				<-child.directory.retired
				childErr = errors.Join(childErr, child.directory.scope.Wait(context.Background()))
			}
			if child.stateStore != nil {
				<-child.stateStore.drained
			}
			if child.stack != nil {
				childErr = errors.Join(childErr, child.stack.WaitDetached(context.Background()))
			}
		}
		err := errors.Join(childErr, scopeErr, p.callbacks.Wait(), p.carriers.Wait())
		if p.registration != nil {
			err = errors.Join(err, p.registration.Abort())
		}
		if err != nil {
			err = runtimeTLS.NewRuntimeCleanupError(err)
		} else if p.baseLease != nil {
			p.baseLease.Release()
		}
		p.mu.Lock()
		p.closeErr = err
		p.mu.Unlock()
	})
	<-p.closeDone
	return p.closeResult()
}

type (
	runtimeEndpointOperation struct {
		done chan struct{}
		err  error
	}
	runtimeEndpointState struct {
		mu                                sync.Mutex
		source                            adapter.RuntimeResourceSource
		options                           option.TailscaleEndpointOptions
		stateDirectory, taildropDirectory string
		generation                        uint64
		reconfig                          map[*runtimeReconfigRegistration]struct{}
		reconfigErr                       error
		physical                          *runtimeEndpointPhysical
		binding                           *runtimeEndpointBinding
		baseContext                       context.Context
		baseSource                        adapter.RuntimeResourceSource
		baseLogger                        log.ContextLogger
		reserved                          *runtimeEndpointPhysical
		operation                         *runtimeEndpointOperation
		openPhysical                      func(*runtimeEndpointPhysical) error
		closing                           bool
		closeOnce                         sync.Once
		closeDone                         chan struct{}
		closeErr                          error
	}
)

func (t *Endpoint) initializeRuntime(options option.TailscaleEndpointOptions) error {
	source, ok := adapter.RuntimeResourceSourceFromContext(t.ctx)
	if !ok {
		return errors.New("Tailscale runtime owner missing")
	}
	// Registrar identity uses the captured configured spelling after expansion;
	// actual default/base/absolute path selection belongs to the fresh child plan.
	options.StateDirectory = os.ExpandEnv(options.StateDirectory)
	options.TaildropDirectory = os.ExpandEnv(options.TaildropDirectory)
	state, taildrop := options.StateDirectory, options.TaildropDirectory
	r := &runtimeEndpointState{source: source, options: cloneRuntimeOptions(options), stateDirectory: state, taildropDirectory: taildrop, closeDone: make(chan struct{})}
	t.runtime = r
	r.openPhysical = t.openRuntimePhysical
	return adapter.DeferConstructionCleanup(t.ctx, t.RuntimeCloseAndWait)
}

func (t *Endpoint) RuntimeValidate() error {
	if t.runtime == nil {
		return errors.New("Tailscale has no private physical lifecycle")
	}
	return nil
}

func (t *Endpoint) RuntimeResourceID() adapter.RuntimeResourceID {
	if t.runtime == nil {
		return adapter.RuntimeResourceID{}
	}
	return t.runtime.source.ID()
}

func (t *Endpoint) PrepareRuntime(stage adapter.StartStage, _ *adapter.Scope) error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	if stage == adapter.StartStateInitialize {
		options := t.runtime.options
		if options.SSHServer != nil && options.SSHServer.Enabled {
			if err := adapter.CheckSecurityFeature(t.ctx, "Tailscale `ssh_server`"); err != nil {
				return err
			}
		}
		for _, route := range options.AdvertiseRoutes {
			if route.Addr().IsUnspecified() && route.Bits() == 0 {
				return errors.New("advertise_routes cannot contain a default route")
			}
		}
		if options.AdvertiseExitNode && options.ExitNode != "" {
			return errors.New("cannot advertise and use an exit node simultaneously")
		}
		return nil
	}
	return nil
}

// RuntimeReservePhysical admits original-run census capacity without acquiring
// a lease, creating a filesystem object, constructing tsnet, or authenticating.
// Sharing an existing identity never reserves another birth or suspends it.
func (t *Endpoint) RuntimeReservePhysical(ctx context.Context) error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	r := t.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return net.ErrClosed
	}
	if r.reserved != nil {
		return r.reserved.reservationErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.generation++
	if r.baseContext == nil || r.baseSource == nil || r.baseLogger == nil {
		return errors.New("Tailscale stable physical base was not supplied")
	}
	baseLease, err := r.baseSource.Acquire()
	if err != nil {
		return err
	}
	physicalContext, cancel := context.WithCancel(r.baseContext)
	callbacks := outbound.NewRuntimeIOFence(nil)
	scope := adapter.NewScope(physicalContext, outbound.WrapRuntimeLogger(r.baseLogger, callbacks))
	p := &runtimeEndpointPhysical{attachments: make(map[*runtimeEndpointBinding]struct{}), baseLease: baseLease, source: r.baseSource, scope: scope, callbacks: callbacks, carriers: outbound.NewRuntimeIOFenceSet(), cancel: cancel, generation: r.generation, constructionDone: make(chan struct{}), closeDone: make(chan struct{}), constructionErr: errors.New("Tailscale construction not complete"), closeErr: errors.New("Tailscale close not complete")}
	p.returns.physical = p
	p.ctx = adapter.ContextWithConstructionScope(context.WithValue(adapter.ContextWithRuntimeResourceSource(scope.Context(), r.baseSource), runtimePhysicalEndpointKey{}, p), scope)
	r.reserved = p // retain the inert evidence holder even if registration fails
	p.begin, err = outbound.RegisterRuntimeOwnedFence(p.ctx, callbacks)
	if err != nil {
		p.reservationErr = err
		return err
	}
	registrationContext := adapter.ContextWithRuntimeTailscaleChildBase(t.ctx, p.ctx)
	p.registration, err = adapter.RegisterRuntimeTailscaleChild(registrationContext, adapter.RuntimeTailscaleChildRequest{
		ResourceID: r.source.ID(), Generation: p.generation, Tag: t.Tag(), StateDirectory: r.stateDirectory, TaildropDirectory: r.taildropDirectory,
		ConstructionDone: p.constructionDone, CloseDone: p.closeDone, ConstructionResult: p.constructionResult, CloseResult: p.closeResult, StoreScopes: p.storeScopes, DirectoryScopes: p.directoryScopes,
	})
	p.reservationErr = err
	return err
}

func (t *Endpoint) RuntimeReleasePhysicalReservation(ctx context.Context) error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	return t.runtime.run(ctx, func() error {
		t.runtime.mu.Lock()
		reserved := t.runtime.reserved
		t.runtime.reserved = nil
		t.runtime.mu.Unlock()
		if reserved == nil {
			return nil
		}
		return reserved.close()
	})
}

func (t *Endpoint) RuntimeStop() {
	if t.runtime == nil {
		return
	}
	t.runtime.mu.Lock()
	p, b := t.runtime.physical, t.runtime.binding
	t.runtime.mu.Unlock()
	if p != nil {
		p.mu.Lock()
		if p.active == b {
			p.active = nil
		}
		p.mu.Unlock()
	}
}

func (t *Endpoint) RuntimeCloseAndWait() error {
	r := t.runtime
	if r == nil {
		return errors.New("Tailscale runtime owner missing")
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closing = true
		operation := r.operation
		r.mu.Unlock()
		r.closeErr = runtimeTLS.NewRuntimeCleanupError(errors.New("Tailscale logical close did not complete"))
		defer close(r.closeDone)
		if operation != nil {
			<-operation.done
		}
		r.mu.Lock()
		p, reserved, b := r.physical, r.reserved, r.binding
		r.mu.Unlock()
		r.closeErr = nil
		if p != nil && b != nil {
			r.closeErr = p.detach(b)
		}
		if b != nil {
			r.closeErr = errors.Join(r.closeErr, b.closeAndWait())
		}
		if reserved != nil {
			r.closeErr = errors.Join(r.closeErr, reserved.close())
		}
		if operation != nil && runtimeTLS.IsRuntimeCleanupIncomplete(operation.err) {
			r.closeErr = runtimeTLS.NewRuntimeCleanupError(errors.Join(r.closeErr, operation.err))
		}
	})
	<-r.closeDone
	return r.closeErr
}

func (r *runtimeEndpointState) run(ctx context.Context, fn func() error) error {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return net.ErrClosed
	}
	if previous := r.operation; previous != nil {
		select {
		case <-previous.done:
		default:
			r.mu.Unlock()
			return errors.New("Tailscale physical operation still running")
		}
	}
	op := &runtimeEndpointOperation{done: make(chan struct{})}
	r.operation = op
	r.mu.Unlock()
	go func() {
		op.err = runtimeTLS.NewRuntimeCleanupError(errors.New("Tailscale physical operation did not return"))
		defer func() {
			if recover() != nil {
				op.err = runtimeTLS.NewRuntimeCleanupError(errors.New("Tailscale physical operation panicked; original child retained"))
			}
			close(op.done)
		}()
		op.err = fn()
	}()
	select {
	case <-op.done:
		return op.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *Endpoint) RuntimeStagePhysical(ctx context.Context) error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	r := t.runtime
	return r.run(ctx, func() error {
		r.mu.Lock()
		existing, reserved := r.physical, r.reserved
		r.mu.Unlock()
		if existing != nil {
			return errors.New("Tailscale logical endpoint physical attachment is single-use")
		}
		if reserved == nil || reserved.registration == nil {
			return errors.New("Tailscale child birth was not reserved before staging")
		}
		p := reserved
		b, err := t.newRuntimeBinding(p)
		if err != nil {
			return err
		}
		if err = p.attach(b); err != nil {
			return errors.Join(err, b.closeAndWait())
		}
		r.mu.Lock()
		r.reserved = nil
		r.physical = p
		r.binding = b
		t.queryOptions = b.query
		r.mu.Unlock()
		p.mu.Lock()
		p.acquisition = true
		p.mu.Unlock()
		// ConstructionDone belongs to this exact holder. A panic cannot masquerade
		// as an empty reservation; retain the failed/partial owner for actual close.
		defer func() {
			if failure := recover(); failure != nil {
				p.constructed(runtimeTLS.NewRuntimeCleanupError(errors.New("Tailscale child construction panicked")))
				panic(failure)
			}
		}()
		if err := p.registration.Prepare(ctx); err != nil {
			p.constructed(err)
			return errors.Join(err, p.close())
		}
		registeredContext := p.registration.Context()
		p.ctx = adapter.ContextWithConstructionScope(context.WithValue(registeredContext, runtimePhysicalEndpointKey{}, p), p.scope)
		if err := r.openPhysical(p); err != nil {
			p.constructed(err)
			return errors.Join(err, p.close())
		}
		return nil
	})
}

func (t *Endpoint) openRuntimePhysical(p *runtimeEndpointPhysical) error {
	raw, err := NewEndpoint(p.ctx, nil, outbound.WrapRuntimeLogger(t.runtime.baseLogger, p.callbacks), t.Tag(), t.runtime.options)
	p.constructed(err)
	if err != nil {
		return err
	}
	child := raw.(*Endpoint)
	p.observe(child, child.directory, child.stateStore)
	if err = p.registration.Constructed(); err != nil {
		return err
	}
	for _, stage := range adapter.ListStartStages {
		if err = p.scope.Start("Tailscale physical child", child, stage); err != nil {
			return err
		}
	}
	return nil
}

func (t *Endpoint) runtimeChild(_ bool) (*Endpoint, func(), error) {
	r := t.runtime
	r.mu.Lock()
	p, b := r.physical, r.binding
	closing := r.closing
	r.mu.Unlock()
	if p == nil || b == nil || closing {
		return nil, nil, net.ErrClosed
	}
	leave, err := p.callbacks.Acquire()
	if err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	child := p.child
	physicalClosing := p.closing
	p.mu.Unlock()
	if child == nil || physicalClosing {
		leave()
		return nil, nil, net.ErrClosed
	}
	return child, leave, nil
}

// The coordinator retains candidate construction leases from this validation
// through Publish or abort, and does not call logical Close concurrently.
// Native failure must never launch an autonomous logical detach.
type RuntimeEndpointPublication struct{ bindings []*runtimeEndpointBinding }

func PrepareRuntimeEndpointPublication(endpoints []*Endpoint) (*RuntimeEndpointPublication, error) {
	result := &RuntimeEndpointPublication{}
	for _, t := range endpoints {
		if err := t.RuntimeValidate(); err != nil {
			return nil, err
		}
		r := t.runtime
		r.mu.Lock()
		p, b, op, closing, reconfigErr := r.physical, r.binding, r.operation, r.closing, r.reconfigErr
		r.mu.Unlock()
		if reconfigErr != nil {
			return nil, reconfigErr
		}
		if closing || p == nil || b == nil || op == nil {
			return nil, errors.New("Tailscale physical preparation incomplete")
		}
		select {
		case <-op.done:
			if op.err != nil {
				return nil, op.err
			}
		default:
			return nil, errors.New("Tailscale physical preparation still running")
		}
		p.mu.Lock()
		_, attached := p.attachments[b]
		ready := attached && !p.closing && p.child != nil
		p.mu.Unlock()
		if !ready {
			return nil, net.ErrClosed
		}
		result.bindings = append(result.bindings, b)
	}
	return result, nil
}

func (p *RuntimeEndpointPublication) Publish() {
	for _, b := range p.bindings {
		owner := b.physical
		owner.mu.Lock()
		owner.active = b
		owner.bootstrap = nil
		owner.mu.Unlock()
	}
}
func cloneRuntimePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
func cloneRuntimeOptions(value option.TailscaleEndpointOptions) option.TailscaleEndpointOptions {
	value.AdvertiseRoutes = slices.Clone(value.AdvertiseRoutes)
	value.AdvertiseTags = slices.Clone(value.AdvertiseTags)
	value.RelayServerStaticEndpoints = slices.Clone(value.RelayServerStaticEndpoints)
	value.RelayServerPort = cloneRuntimePointer(value.RelayServerPort)
	value.SSHServer = cloneRuntimePointer(value.SSHServer)
	value.Inet4BindAddress = cloneRuntimePointer(value.Inet4BindAddress)
	value.Inet6BindAddress = cloneRuntimePointer(value.Inet6BindAddress)
	value.UDPFragment = cloneRuntimePointer(value.UDPFragment)
	value.NetworkStrategy = cloneRuntimePointer(value.NetworkStrategy)
	value.NetworkType = slices.Clone(value.NetworkType)
	value.FallbackNetworkType = slices.Clone(value.FallbackNetworkType)
	value.DomainResolver = cloneRuntimePointer(value.DomainResolver)
	if resolver := value.DomainResolver; resolver != nil {
		resolver.Policy = cloneRuntimePointer(resolver.Policy)
		resolver.RewriteTTL = cloneRuntimePointer(resolver.RewriteTTL)
		resolver.ClientSubnet = cloneRuntimePointer(resolver.ClientSubnet)
	}
	return value
}

var _ endpoint.RuntimePreparedEndpoint = (*Endpoint)(nil)
