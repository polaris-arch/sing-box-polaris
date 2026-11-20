package lifecycle

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

// EndpointResolvers owns work, child scopes and cancellation for pushed DNS.
// The endpoint transport supplies its current resolver snapshot and clears its
// own route state after work, producers and the endpoint link have joined.
type EndpointResolvers struct {
	work            IdleResolvers
	producers       Work
	scopes          Scopes
	operationCtx    context.Context
	operationCancel context.CancelFunc
	producerCtx     context.Context
	producerCancel  context.CancelFunc
	endpointUnlink  func()
	logger          log.ContextLogger
	resolvers       func() []adapter.DNSTransport
	clear           func()

	constructionOwned bool
	startOnce         sync.Once
	startErr          error
	closeOnce         sync.Once
	closeErr          error
}

func (r *EndpointResolvers) Init(ctx context.Context, logger log.ContextLogger, resolvers func() []adapter.DNSTransport, clear func()) error {
	r.operationCtx, r.operationCancel = context.WithCancel(ctx)
	r.producerCtx, r.producerCancel = context.WithCancel(r.operationCtx)
	r.logger = logger
	r.resolvers = resolvers
	r.clear = clear
	var err error
	r.constructionOwned, err = ConstructionCleanup(ctx, r.Close)
	return err
}

func (r *EndpointResolvers) ReserveStart(scope *adapter.Scope) (func(), error) {
	r.startOnce.Do(func() {
		if !r.constructionOwned {
			_, r.startErr = ConstructionCleanup(adapter.ContextWithConstructionScope(context.Background(), scope), r.Close)
		}
	})
	if r.startErr != nil {
		return nil, r.startErr
	}
	done, ok := r.work.Reserve()
	if !ok {
		return nil, ErrStopped
	}
	return done, nil
}

// LinkProducer is called during endpoint attachment, before publishing the
// transport to endpoint callbacks.
func (r *EndpointResolvers) LinkProducer(ctx context.Context) {
	r.producerCtx, r.endpointUnlink = LinkCancellation(r.producerCtx, ctx)
}

func (r *EndpointResolvers) Operation(ctx context.Context, source adapter.RuntimeResourceSource) (context.Context, func(), error) {
	return r.work.Operation(ctx, source)
}

func (r *EndpointResolvers) OperationContext() context.Context { return r.operationCtx }
func (r *EndpointResolvers) ReserveProducer() (func(), bool)   { return r.producers.Reserve() }
func (r *EndpointResolvers) WaitReady() error                  { return r.scopes.WaitReady(r.producerCtx) }

func (r *EndpointResolvers) NewScope() (*adapter.Scope, error) {
	return r.scopes.New(r.operationCtx, r.logger)
}
func (r *EndpointResolvers) Retire(scope *adapter.Scope) { r.scopes.Retire(scope) }

func (r *EndpointResolvers) StartResolver(resolver adapter.DNSTransport, scope *adapter.Scope) error {
	return r.work.Start(resolver, scope, r.logger)
}

func (r *EndpointResolvers) SetKeepIdleConnections(keep bool) { r.work.SetKeepIdleConnections(keep) }
func (r *EndpointResolvers) CloseIdleConnections()            { r.work.CloseIdleConnections() }

func (r *EndpointResolvers) StopRuntimeProducers() {
	r.producers.Seal()
	if r.producerCancel != nil {
		r.producerCancel()
	}
	if r.resolvers != nil {
		for _, resolver := range r.resolvers() {
			if producer, ok := resolver.(interface{ StopRuntimeProducers() }); ok {
				producer.StopRuntimeProducers()
			}
		}
	}
}

func (r *EndpointResolvers) StopRuntimeOperations() {
	r.work.Seal()
	if r.operationCancel != nil {
		r.operationCancel()
	}
	r.StopRuntimeProducers()
	r.scopes.Stop()
}

func (r *EndpointResolvers) Close() error {
	r.closeOnce.Do(func() {
		r.StopRuntimeOperations()
		r.work.Wait()
		r.producers.Wait()
		if r.endpointUnlink != nil {
			r.endpointUnlink()
		}
		if r.clear != nil {
			r.clear()
		}
		scopeErr := r.scopes.Close()
		r.closeErr = Uncertain("endpoint DNS resolver cohorts", errors.Join(scopeErr, r.work.CleanupError()))
	})
	return r.closeErr
}
