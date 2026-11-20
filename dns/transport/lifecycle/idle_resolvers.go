package lifecycle

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

// IdleResolvers uses the component's existing work gate for child start and
// idle operations. It includes unpublished and retiring children until their
// scope actually closes.
type IdleResolvers struct {
	Work
	access      sync.Mutex
	disableIdle bool
	keepers     map[adapter.IdleConnectionKeeper]struct{}
	cleanupErr  error
}

func (r *IdleResolvers) SetKeepIdleConnections(keep bool) {
	done, ok := r.Reserve()
	if !ok {
		return
	}
	defer done()
	r.access.Lock()
	defer r.access.Unlock()
	r.disableIdle = !keep
	for keeper := range r.keepers {
		keeper.SetKeepIdleConnections(keep)
	}
}

func (r *IdleResolvers) CloseIdleConnections() {
	done, ok := r.Reserve()
	if !ok {
		return
	}
	defer done()
	r.access.Lock()
	defer r.access.Unlock()
	for keeper := range r.keepers {
		keeper.CloseIdleConnections()
	}
}

// Start keeps the private child scope off the retiring parent's cleanup stack
// until the child finishes Start and has registered all its cleanup.
func (r *IdleResolvers) Start(resolver adapter.DNSTransport, scope *adapter.Scope, logger log.ContextLogger) error {
	done, ok := r.Reserve()
	if !ok {
		return ErrStopped
	}
	defer done()
	keeper, ok := resolver.(adapter.IdleConnectionKeeper)
	if !ok {
		return errors.New("endpoint DNS resolver requires idle-only connection control")
	}
	childScope := adapter.NewScope(scope.Context(), logger)
	startErr := resolver.Start(adapter.StartStateStart, childScope)
	if startErr == nil {
		// Apply the current policy and register together, before publication.
		r.access.Lock()
		keeper.SetKeepIdleConnections(!r.disableIdle)
		if r.keepers == nil {
			r.keepers = make(map[adapter.IdleConnectionKeeper]struct{})
		}
		r.keepers[keeper] = struct{}{}
		r.access.Unlock()
	}
	cleanupErr := adapter.DeferConstructionCleanup(adapter.ContextWithConstructionScope(context.Background(), scope), func() error {
		// Removal joins admitted idle calls. Child close runs after unlocking.
		r.access.Lock()
		delete(r.keepers, keeper)
		r.access.Unlock()
		err := Uncertain("endpoint DNS child resolver", childScope.Close())
		if err != nil {
			r.access.Lock()
			r.cleanupErr = errors.Join(r.cleanupErr, err)
			r.access.Unlock()
		}
		return err
	})
	return errors.Join(startErr, cleanupErr, scope.Context().Err())
}

func (r *IdleResolvers) CleanupError() error {
	r.access.Lock()
	defer r.access.Unlock()
	return r.cleanupErr
}
