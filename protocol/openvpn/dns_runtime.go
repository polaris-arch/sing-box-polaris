package openvpn

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

func (t *DNSTransport) StopRuntimeProducers() {
	t.producers.Seal()
	if t.producerCancel != nil {
		t.producerCancel()
	}
	t.access.RLock()
	resolvers := t.collectResolversLocked()
	t.access.RUnlock()
	for _, resolver := range resolvers {
		if producer, ok := resolver.(interface{ StopRuntimeProducers() }); ok {
			producer.StopRuntimeProducers()
		}
	}
}

func (t *DNSTransport) StopRuntimeOperations() {
	t.work.Seal()
	if t.operationCancel != nil {
		t.operationCancel()
	}
	t.StopRuntimeProducers()
	t.scopes.Stop()
}

func (t *DNSTransport) close() error {
	t.closeOnce.Do(func() {
		t.StopRuntimeOperations()
		t.work.Wait()
		t.producers.Wait()
		if t.endpointUnlink != nil {
			t.endpointUnlink()
		}
		t.access.Lock()
		t.closed = true
		t.routes = nil
		t.searchDomains = nil
		t.serverAddresses = nil
		t.defaultResolvers = nil
		t.resolverScope = nil
		t.access.Unlock()
		scopeErr := t.scopes.Close()
		t.idleAccess.Lock()
		childErr := t.idleCleanupErr
		t.idleAccess.Unlock()
		t.closeErr = lifecycle.Uncertain("endpoint DNS resolver cohorts", errors.Join(scopeErr, childErr))
	})
	return t.closeErr
}

// Idle policy covers all children owned by this wrapper, including candidates
// and retired cohorts whose in-flight queries have not finished. It never uses
// Reset: only each child knows which carriers are currently idle.
func (t *DNSTransport) SetKeepIdleConnections(keep bool) {
	done, ok := t.work.Reserve()
	if !ok {
		return
	}
	defer done()
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	t.disableIdleConnections = !keep
	for resolver := range t.idleResolvers {
		resolver.SetKeepIdleConnections(keep)
	}
}

func (t *DNSTransport) CloseIdleConnections() {
	done, ok := t.work.Reserve()
	if !ok {
		return
	}
	defer done()
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	for resolver := range t.idleResolvers {
		resolver.CloseIdleConnections()
	}
}

// The private start scope is not published until Start returns. This prevents
// a retiring owner from closing a partly initialized child and losing a cleanup
// registered by Start after the owner's scope has already drained.
func (t *DNSTransport) startDNSResolver(resolver adapter.DNSTransport, scope *adapter.Scope) error {
	done, ok := t.work.Reserve()
	if !ok {
		return lifecycle.ErrStopped
	}
	defer done()
	keeper, ok := resolver.(adapter.IdleConnectionKeeper)
	if !ok {
		return errors.New("endpoint DNS resolver requires idle-only connection control")
	}
	childScope := adapter.NewScope(scope.Context(), t.logger)
	startErr := resolver.Start(adapter.StartStateStart, childScope)
	if startErr == nil {
		// Registration and policy application are atomic with a concurrent
		// setter, and complete before route/default publication.
		t.idleAccess.Lock()
		keeper.SetKeepIdleConnections(!t.disableIdleConnections)
		if t.idleResolvers == nil {
			t.idleResolvers = make(map[adapter.IdleConnectionKeeper]struct{})
		}
		t.idleResolvers[keeper] = struct{}{}
		t.idleAccess.Unlock()
	}
	cleanupErr := adapter.DeferConstructionCleanup(adapter.ContextWithConstructionScope(context.Background(), scope), func() error {
		// Serialize removal with admitted idle calls, then close outside the
		// registry lock. New callers can no longer reach this child.
		t.idleAccess.Lock()
		delete(t.idleResolvers, keeper)
		t.idleAccess.Unlock()
		err := lifecycle.Uncertain("endpoint DNS child resolver", childScope.Close())
		if err != nil {
			t.idleAccess.Lock()
			t.idleCleanupErr = errors.Join(t.idleCleanupErr, err)
			t.idleAccess.Unlock()
		}
		return err
	})
	return errors.Join(startErr, cleanupErr, scope.Context().Err())
}
