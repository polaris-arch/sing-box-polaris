package route

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var (
	errRuntimeReferenceStopped = errors.New("runtime reference observer stopped")
	errRuntimeReferencePaused = errors.New("runtime reference observer paused")
)

// RuntimeReferenceOptions is a private, immutable census recipe, prepared
// without invoking any component. The builder detaches all nested rule fields.
// Preparing this value never starts an observer or changes current idle policy.
type RuntimeReferenceOptions struct {
	rules []option.Rule
	dnsRules []option.DNSRule
	staticOutbounds []string
	staticTransports []string
}

func NewRuntimeReferenceOptions(ctx context.Context, options option.Options) (*RuntimeReferenceOptions, error) {
	var input struct {
		Rules []option.Rule `json:"rules"`
		DNSRules []option.DNSRule `json:"dns_rules"`
	}
	if options.Route != nil { input.Rules = options.Route.Rules }
	if options.DNS != nil { input.DNSRules = options.DNS.Rules }
	content, err := json.MarshalContext(ctx, input)
	if err != nil { return nil, err }
	var frozen struct {
		Rules []option.Rule `json:"rules"`
		DNSRules []option.DNSRule `json:"dns_rules"`
	}
	if err := json.UnmarshalContext(ctx, content, &frozen); err != nil { return nil, err }
	result := &RuntimeReferenceOptions{rules: frozen.Rules, dnsRules: frozen.DNSRules}
	if options.NTP != nil && options.NTP.Enabled && options.NTP.Detour != "" {
		result.staticOutbounds = append(result.staticOutbounds, options.NTP.Detour)
	}
	for _, outbound := range options.Outbounds { result.staticTransports = appendDomainResolver(result.staticTransports, outbound.Options) }
	for _, endpoint := range options.Endpoints { result.staticTransports = appendDomainResolver(result.staticTransports, endpoint.Options) }
	return result, nil
}

// RuntimeReferenceSnapshot transfers one admitted current graph handle to the
// observer. Options, manager inventories and Resources must be sealed for that
// graph. Resources maps actual object identity to allocation identity, not tags;
// a provider must never resolve an old object through the new tag catalog.
// StableResource owns the stable ingress/service/HTTP inventories and observer
// dependencies. Mode is sampled by the provider at snapshot acquisition.
type RuntimeReferenceSnapshot struct {
	Lease adapter.RuntimeLease
	Options *RuntimeReferenceOptions
	Inbounds adapter.InboundManager
	Services adapter.ServiceManager
	HTTPClient adapter.HTTPClientManager
	Mode string
	StableResource adapter.RuntimeResourceID
	Resources map[any]adapter.RuntimeResourceID
}

type RuntimeReferenceProvider interface {
	AcquireReferenceSnapshot() (RuntimeReferenceSnapshot, error)
}

// Registration is one-time, payload-free, and must return actual unregistration
// even when partially failing. An unregister error is retained as uncertainty.
// It need not join a previously captured Emit: admission sealing plus worker
// completion prevents such an Emit from accessing graph resources afterward.
type RuntimeReferenceHooks interface {
	RegisterReferenceHook(*observable.Subscriber[struct{}]) (unregister func() error, err error)
}

// RuntimeReferenceManager is one stable lifecycle adapter under the existing
// resource owner. It is not another resource close authority. Its owner retains
// a stable dependency reservation until WaitStopped reports actual success.
// Never hold coordinator, graph, admission or component locks across Pause,
// CloseIdleConnections, Close or WaitStopped.
type RuntimeReferenceManager struct {
	logger log.ContextLogger
	provider RuntimeReferenceProvider
	hooks RuntimeReferenceHooks
	pauseManager pause.Manager
	calculator *ReferenceManager
	subscriber *observable.Subscriber[struct{}]
	commands chan runtimeReferenceCommand
	stop chan struct{}
	setupDone chan struct{}
	workerDone chan struct{}
	stoppedDone chan struct{}
	mu sync.Mutex
	started bool
	active bool
	stopping bool
	pauses uint64
	busy bool
	idle chan struct{}
	failure error
	unregister []func() error // written only by Start, consumed after setupDone
	callbacks sync.WaitGroup // Add under mu, prohibited after stopping
	quarantined []*runtimeReferenceReservation
}

type runtimeReferenceCommand struct { result chan error }

type runtimeReferenceReservation struct {
	snapshot RuntimeReferenceSnapshot
	resources []adapter.RuntimeResourceLease
}

func NewRuntimeReferenceManager(ctx context.Context, logger log.ContextLogger, provider RuntimeReferenceProvider, hooks RuntimeReferenceHooks) *RuntimeReferenceManager {
	idle := make(chan struct{})
	close(idle)
	return &RuntimeReferenceManager{
		logger: logger, provider: provider, hooks: hooks,
		pauseManager: service.FromContext[pause.Manager](ctx),
		calculator: &ReferenceManager{logger: logger},
		subscriber: observable.NewSubscriber[struct{}](1),
		commands: make(chan runtimeReferenceCommand),
		stop: make(chan struct{}), setupDone: make(chan struct{}),
		workerDone: make(chan struct{}), stoppedDone: make(chan struct{}), idle: idle,
	}
}

func (m *RuntimeReferenceManager) Name() string { return "runtime reference manager" }

func (m *RuntimeReferenceManager) Start(stage adapter.StartStage, scope *adapter.Scope) (err error) {
	if stage != adapter.StartStateStarted { return nil }
	m.mu.Lock()
	if m.stopping { m.mu.Unlock(); return errRuntimeReferenceStopped }
	if m.started { m.mu.Unlock(); return errors.New("runtime reference observer already started") }
	m.started = true
	m.mu.Unlock()
	// Construction cleanup atomically registers with the supplied scope, or
	// runs immediately after scope cancellation. Plain Scope.Add can append
	// after its cleanup stack was detached, so it is not safe for this interval.
	// Before setupDone, only nonjoining Stop may execute on this Start stack.
	cleanupContext := adapter.ContextWithConstructionScope(scope.Context(), scope)
	defer func() {
		if value := recover(); value != nil { err = fmt.Errorf("reference observer setup panic: %v", value) }
		if err == nil { err = scope.Context().Err() }
		if err != nil { m.recordFailure(err); m.Stop() }
		go m.loop()
		close(m.setupDone)
		// A synchronous late cleanup can now join actual setup/worker completion.
		if cleanupErr := adapter.DeferConstructionCleanup(cleanupContext, m.Close); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
		if scopeErr := scope.Context().Err(); scopeErr != nil {
			// Cancellation after completed setup may already have joined a
			// successful cleanup. It is a Start error, not new uncertainty.
			if err == nil { err = scopeErr }
			m.Stop()
		}
	}()
	if err := adapter.DeferConstructionCleanup(cleanupContext, func() error { m.Stop(); return nil }); err != nil { return err }
	if err := scope.Context().Err(); err != nil { return err }
	if m.provider == nil || m.hooks == nil { return errors.New("runtime reference provider and hooks required") }
	unregister, hookErr := m.hooks.RegisterReferenceHook(m.subscriber)
	if unregister != nil { m.unregister = append(m.unregister, unregister) }
	if hookErr != nil { return hookErr }
	if unregister == nil { return errors.New("runtime reference hook has no unregister") }
	if m.pauseManager != nil {
		callback := m.pauseManager.RegisterCallback(m.pauseChanged)
		if callback == nil { return errors.New("runtime reference pause callback registration failed") }
		m.unregister = append(m.unregister, func() error { m.pauseManager.UnregisterCallback(callback); return nil })
	}
	return nil
}

// Activate is called only after the first graph has been published. It queues
// one census, including events received during dormant setup. It cannot restart
// a stopped/failed worker or undo any outstanding publication pause.
func (m *RuntimeReferenceManager) Activate() error {
	m.mu.Lock()
	if m.stopping { m.mu.Unlock(); return errRuntimeReferenceStopped }
	if m.failure != nil { err := m.failure; m.mu.Unlock(); return err }
	if !m.started { m.mu.Unlock(); return errors.New("runtime reference observer not started") }
	m.active = true
	m.mu.Unlock()
	m.subscriber.Emit(struct{}{})
	return nil
}

// RuntimeReferencePause owns exactly one admission pause. A failed/timed-out
// wait still returns the token; the caller must Resume it on abort. Publication
// is permitted only after Pause returned nil error, and while this token remains
// held. Resume is not proof that a candidate was published.
type RuntimeReferencePause struct {
	manager *RuntimeReferenceManager
	once *sync.Once // value copies share the same owned pause
}

func (m *RuntimeReferenceManager) Pause(ctx context.Context) (*RuntimeReferencePause, error) {
	m.mu.Lock()
	if m.stopping { m.mu.Unlock(); return nil, errRuntimeReferenceStopped }
	if m.pauses == ^uint64(0) { m.mu.Unlock(); return nil, errors.New("reference pause overflow") }
	m.pauses++
	token := &RuntimeReferencePause{manager: m, once: new(sync.Once)}
	idle := m.idle
	m.mu.Unlock()
	select {
	case <-idle:
	case <-ctx.Done(): return token, ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping { return token, errRuntimeReferenceStopped }
	if m.failure != nil { return token, m.failure }
	if err := ctx.Err(); err != nil { return token, err }
	return token, nil
}

func (p *RuntimeReferencePause) Resume() {
	if p == nil || p.once == nil { return }
	p.once.Do(func() {
		m := p.manager
		m.mu.Lock()
		m.pauses--
		wake := m.pauses == 0 && m.active && !m.stopping && m.failure == nil
		m.mu.Unlock()
		if wake { m.subscriber.Emit(struct{}{}) }
	})
}

func (m *RuntimeReferenceManager) pauseChanged(event int) {
	if event != pause.EventDevicePaused && event != pause.EventDeviceWake { return }
	m.mu.Lock()
	if m.stopping { m.mu.Unlock(); return }
	m.callbacks.Add(1)
	m.mu.Unlock()
	defer m.callbacks.Done()
	// The event carries no captured graph, resource, mode or pause value.
	m.subscriber.Emit(struct{}{})
}

func (m *RuntimeReferenceManager) begin() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping { return errRuntimeReferenceStopped }
	if m.failure != nil { return m.failure }
	if !m.active || m.pauses != 0 { return errRuntimeReferencePaused }
	m.busy = true
	m.idle = make(chan struct{})
	return nil
}

func (m *RuntimeReferenceManager) finish() {
	m.mu.Lock()
	if m.busy { m.busy = false; close(m.idle) }
	m.mu.Unlock()
}

func (m *RuntimeReferenceManager) loop() {
	defer func() {
		if value := recover(); value != nil {
			m.recordFailure(fmt.Errorf("reference observer worker panic: %v", value))
			m.finish()
			m.Stop()
		}
		close(m.workerDone)
	}()
	subscription, _ := m.subscriber.Subscription()
	for {
		select {
		case <-m.stop: return
		case <-subscription:
			if m.begin() != nil { continue }
			m.run(false)
			m.finish()
		case command := <-m.commands:
			err := m.begin()
			if err == nil { err = m.run(true); m.finish() }
			command.result <- err
		}
	}
}

// CloseIdleConnections enters the same fenced worker as automatic census work.
// Caller timeout is observation only: an admitted operation keeps its graph and
// allocation handles until its actual callbacks complete. This only invokes the
// explicit idle-only interface, never Reset, Close or active-flow interruption.
func (m *RuntimeReferenceManager) CloseIdleConnections(ctx context.Context) error {
	command := runtimeReferenceCommand{result: make(chan error, 1)}
	select {
	case <-m.stop: return errRuntimeReferenceStopped
	case <-ctx.Done(): return ctx.Err()
	case m.commands <- command:
	}
	select {
	case err := <-command.result: return err
	case <-m.stop: return errRuntimeReferenceStopped
	case <-ctx.Done(): return ctx.Err()
	}
}

func (m *RuntimeReferenceManager) run(closeIdle bool) (err error) {
	reservation := new(runtimeReferenceReservation)
	completed := false
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("reference observer effect panic: %v", value)
			// A panic is not evidence that a component's native/asynchronous
			// effect has ended. Keep the actual handles reachable and charged.
			m.mu.Lock(); m.quarantined = append(m.quarantined, reservation); m.mu.Unlock()
		} else {
			completed = true
		}
		if completed { reservation.release() }
		if err != nil { m.recordFailure(err) }
	}()
	reservation.snapshot, err = m.provider.AcquireReferenceSnapshot()
	if err != nil {
		m.mu.Lock(); stopping := m.stopping; m.mu.Unlock()
		if stopping && reservation.snapshot.Lease == nil { return nil }
		return err
	}
	inventory, err := reservation.prepare()
	if err != nil { return err }
	if m.pauseManager != nil { inventory.devicePaused = m.pauseManager.IsDevicePaused() }
	if closeIdle {
		for _, outbound := range inventory.outbounds.Outbounds() {
			if keeper, ok := outbound.(adapter.IdleConnectionKeeper); ok { keeper.CloseIdleConnections() }
		}
		for _, transport := range inventory.transports.Transports() {
			transport.(adapter.IdleConnectionKeeper).CloseIdleConnections()
		}
	} else {
		m.calculator.updateInventory(inventory)
	}
	return nil
}

func (r *runtimeReferenceReservation) prepare() (referenceInventory, error) {
	s := r.snapshot
	if s.Lease == nil || s.Options == nil { return referenceInventory{}, errors.New("incomplete reference graph snapshot") }
	view := s.Lease.View()
	if view == nil || view.OutboundManager() == nil || view.EndpointManager() == nil || view.DNSTransportManager() == nil || view.NetworkManager() == nil || s.Inbounds == nil || s.Services == nil || s.HTTPClient == nil {
		return referenceInventory{}, errors.New("incomplete reference manager inventory")
	}
	retained := make(map[adapter.RuntimeResourceID]bool)
	retain := func(id adapter.RuntimeResourceID) error {
		if id.Incarnation == "" || id.Sequence == 0 { return errors.New("reference resource has no allocation identity") }
		if retained[id] { return nil }
		lease, err := s.Lease.RetainResource(id)
		if err != nil { return err }
		if lease == nil { return errors.New("reference resource retention returned no handle") }
		r.resources = append(r.resources, lease)
		retained[id] = true
		return nil
	}
	if err := retain(s.StableResource); err != nil { return referenceInventory{}, err }
	retainObject := func(object any) error {
		if object == nil || !reflect.TypeOf(object).Comparable() { return errors.New("reference resource identity is not comparable") }
		id, ok := s.Resources[object]
		if !ok { return errors.New("reference resource missing from immutable graph inventory") }
		return retain(id)
	}
	// Graph-owned HTTP inventories carry their own allocation identity. Legacy
	// stable snapshots remain covered by StableResource.
	if reflect.TypeOf(s.HTTPClient).Comparable() {
  if _, owned := s.Resources[s.HTTPClient]; owned { if err := retainObject(s.HTTPClient); err != nil { return referenceInventory{},err } }
 }
	for _, outbound := range view.OutboundManager().Outbounds() {
		if err := retainObject(outbound); err != nil { return referenceInventory{}, err }
	}
	// Retain the exact logical endpoint allocation before reading its references
	// or applying its existing on-demand policy. The observer's Pause joins these
	// effects before graph publication; shared physical adapters join their tails.
	for _, endpoint := range view.EndpointManager().Endpoints() {
		if err := retainObject(endpoint); err != nil { return referenceInventory{}, err }
	}
	for _, transport := range view.DNSTransportManager().Transports() {
		if err := retainObject(transport); err != nil { return referenceInventory{}, err }
		if _, ok := transport.(adapter.IdleConnectionKeeper); !ok { return referenceInventory{}, errors.New("runtime DNS reference adapter requires idle-only connection control") }
	}
	return referenceInventory{
		rules: s.Options.rules, dnsRules: s.Options.dnsRules,
		staticOutbounds: s.Options.staticOutbounds, staticTransports: s.Options.staticTransports,
		mode: s.Mode, outbounds: view.OutboundManager(), endpoints: view.EndpointManager(),
		inbounds: s.Inbounds, services: s.Services, transports: view.DNSTransportManager(),
		network: view.NetworkManager(), httpClient: s.HTTPClient,
		// Runtime reconciliation must not infer that an unreferenced transport
		// has no retained queries. Reset is deliberately forbidden here.
		allowReset: false,
	}, nil
}

func (r *runtimeReferenceReservation) release() {
	for index := len(r.resources) - 1; index >= 0; index-- { r.resources[index].Release() }
	if r.snapshot.Lease != nil { r.snapshot.Lease.Release() }
}

func (m *RuntimeReferenceManager) recordFailure(err error) {
	if err == nil { return }
	m.mu.Lock(); m.failure = errors.Join(m.failure, err); m.mu.Unlock()
}

// Stop only seals admission and schedules the owned cleanup. It never joins a
// callback on its own stack, including when called by a blocked idle effect.
func (m *RuntimeReferenceManager) Stop() {
	m.mu.Lock()
	if m.stopping { m.mu.Unlock(); return }
	m.stopping = true
	close(m.stop)
	if !m.started { close(m.setupDone); close(m.workerDone) }
	m.mu.Unlock()
	go m.stopAndJoin()
}

func (m *RuntimeReferenceManager) stopAndJoin() {
	defer close(m.stoppedDone)
	<-m.setupDone
	for index := len(m.unregister) - 1; index >= 0; index-- {
		err := func() (err error) {
			defer func() { if value := recover(); value != nil { err = fmt.Errorf("reference producer unregister panic: %v", value) } }()
			return m.unregister[index]()
		}()
		m.recordFailure(err)
	}
	m.callbacks.Wait()
	m.recordFailure(m.subscriber.Close()) // sole subscriber-close owner
	<-m.workerDone
}

// WaitStopped is an observation, not permission to discard live reservations.
// Errors are sticky; the owning ResourceOwner must keep its dependency charged.
func (m *RuntimeReferenceManager) WaitStopped(ctx context.Context) error {
	select {
	case <-m.stoppedDone:
	default:
		select {
		case <-m.stoppedDone:
		case <-ctx.Done(): return ctx.Err()
		}
	}
	m.mu.Lock(); defer m.mu.Unlock()
	return m.failure
}

func (m *RuntimeReferenceManager) Close() error {
	m.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), C.StopTimeout)
	defer cancel()
	if err := m.WaitStopped(ctx); err != nil {
		// Scope.Close filters closed/canceled errors (including deadlines).
		// At this ownership boundary an incomplete join is uncertainty, not
		// successful cleanup. Keep diagnostics without cancellation unwrapping.
		return fmt.Errorf("runtime reference observer cleanup incomplete: %v", err)
	}
	return nil
}

var _ adapter.LifecycleService = (*RuntimeReferenceManager)(nil)
