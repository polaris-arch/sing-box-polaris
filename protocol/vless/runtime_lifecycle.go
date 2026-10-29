package vless

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
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
	var result []error
	if h.multiplexDialer != nil {
		result = append(result, outbound.CloseRuntimeResource(h.runtimeContext, "vless multiplexDialer", h.multiplexDialer))
	}
	if h.transport != nil {
		result = append(result, outbound.CloseRuntimeResource(h.runtimeContext, "vless transport", h.transport))
	}
	return errors.Join(result...)
}

// Final shutdown only. Ordinary retirement seals producer roots while old
// foreground streams retain the transport; it must not invoke this hook.
func (h *Outbound) StopRuntimeOperations() {
	if transport, ok := h.transport.(interface{ StopRuntimeOperations() }); ok {
		transport.StopRuntimeOperations()
	}
}
