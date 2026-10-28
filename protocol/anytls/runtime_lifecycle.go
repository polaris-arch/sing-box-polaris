package anytls

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/logger"
)

func (h *Outbound) initRuntimeCleanup(ctx context.Context) error {
	h.runtimeContext = ctx
	h.runtimeSource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	h.runtimeCleanup = outbound.OnceRuntimeCleanup(h.closeRuntimeResources)
	return nil
}

func (h *Outbound) finishRuntimeConstruction(ctx context.Context) error {
	var err error
	h.constructionCleanup, err = outbound.RegisterRuntimeCleanup(ctx, h.runtimeCleanup)
	return err
}

func (h *Outbound) registerRuntimeStart(scope *adapter.Scope) error {
	if err := scope.Context().Err(); err != nil {
		_ = h.runtimeCleanup()
		return err
	}
	if h.constructionCleanup {
		return nil
	}
	ctx := adapter.ContextWithConstructionScope(scope.Context(), scope)
	var err error
	h.constructionCleanup, err = outbound.RegisterRuntimeCleanup(ctx, h.runtimeCleanup)
	return err
}

func (h *Outbound) closeRuntimeResources() error {
	if h.runtimeFences == nil {
		return nil
	}
	h.runtimeFences.Stop()
	h.runtimeCancel()
	_ = h.runtimeCallbacks.Close()
	if h.client != nil {
		h.runtimeFences.Record(h.client.Close())
	}
	return errors.Join(h.runtimeFences.Wait(), h.runtimeCallbacks.Wait())
}

func (h *Outbound) initRuntimePool() {
	h.runtimeFences = outbound.NewRuntimeIOFenceSet()
	h.runtimeCallbacks = outbound.NewRuntimeIOFence(nil)
	h.runtimeStop, h.runtimeCancel = context.WithCancel(context.Background())
}

func (h *Outbound) dialRuntimeSession(ctx context.Context) (net.Conn, error) {
	ctx = adapter.ContextForMultiplexSession(ctx)
	if h.runtimeSource == nil {
		return h.dialer.DialTLSContext(ctx, h.server)
	}
	creation, err := h.runtimeFences.Begin()
	if err != nil {
		return nil, err
	}
	defer creation.Done()
	ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, h.runtimeSource)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(h.runtimeStop, func() { defer close(callbackDone); cancel() })
	defer func() {
		if !stop() {
			<-callbackDone
		}
		cancel()
	}()
	conn, err := h.dialer.DialTLSContext(ctx, h.server)
	if err != nil {
		if conn != nil {
			_, fence := outbound.WrapRuntimeOwnedConn(conn)
			h.runtimeFences.Record(fence.RuntimeCloseAndWait())
		}
		return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedConn(conn)
	if err := creation.Register(fence); err != nil {
		return nil, err
	}
	return wrapped, nil
}

// The pinned AnyTLS client/session's only external asynchronous callback is
// logging. Timer/stream tails otherwise touch private buffers/maps and the
// fenced raw carrier; this boundary prevents late logs reaching a retired sink.
func (h *Outbound) runtimeLogger(base logger.ContextLogger) logger.ContextLogger {
	return outbound.WrapRuntimeLogger(base, h.runtimeCallbacks)
}
