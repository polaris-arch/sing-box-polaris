package route

import (
	"context"
	"errors"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
)

// The route mark is constructor configuration, not mutable OS monitor state.
// Existing dialers retain their original mark while the next graph prepares.
type runtimeNetworkMarkView struct {
	adapter.NetworkManager
	mark       uint32
	autoDetect bool
}

func (v *runtimeNetworkMarkView) RegisterAutoRedirectOutputMark(mark uint32) error {
	if mark == 0 || mark != v.mark {
		return errors.New("auto-redirect mark differs from prepared graph declaration")
	}
	return nil
}
func (v *runtimeNetworkMarkView) AutoRedirectOutputMark() uint32 { return v.mark }
func (v *runtimeNetworkMarkView) AutoRedirectOutputMarkFunc() control.Func {
	mark := v.mark
	return func(network, address string, conn syscall.RawConn) error {
		if mark == 0 {
			return nil
		}
		return control.RoutingMark(mark)(network, address, conn)
	}
}

func NewRuntimeNetworkOptionsView(owner adapter.NetworkManager, defaults adapter.NetworkOptions, mark uint32, autoDetect ...bool) (adapter.NetworkManager, error) {
	view, err := NewNetworkOptionsView(owner, defaults)
	if err != nil {
		return nil, err
	}
	enabled := owner.AutoDetectInterface()
	if len(autoDetect) > 0 {
		enabled = autoDetect[0]
	}
	if enabled && owner.AutoDetectInterfaceFunc() == nil {
		return nil, errors.New("auto-detect interface monitor unavailable on this host")
	}
	return &runtimeNetworkMarkView{NetworkManager: view, mark: mark, autoDetect: enabled}, nil
}

func ContextWithRuntimeNetworkOptions(ctx context.Context, owner adapter.NetworkManager, options option.RouteOptions, mark uint32) (context.Context, error) {
	defaults, err := BuildNetworkOptions(options)
	if err != nil {
		return nil, err
	}
	view, err := NewRuntimeNetworkOptionsView(owner, defaults, mark, options.AutoDetectInterface)
	if err != nil {
		return nil, err
	}
	child := service.ExtendContext(service.ContextWithDefaultRegistry(ctx))
	service.MustRegister[adapter.NetworkManager](child, view)
	return child, nil
}

func (v *runtimeNetworkMarkView) AutoDetectInterface() bool { return v.autoDetect }
func (v *runtimeNetworkMarkView) AutoDetectInterfaceFunc() control.Func {
	if !v.autoDetect {
		return nil
	}
	return v.NetworkManager.AutoDetectInterfaceFunc()
}
