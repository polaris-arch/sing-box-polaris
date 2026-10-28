package dialer

import (
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

func bindInterfaceControl(platform adapter.PlatformInterface, finder control.InterfaceFinder, interfaceName string) (control.Func, error) {
	if C.IsAndroid {
		return platformBindInterfaceControl(platform, interfaceName)
	}
	return control.BindToInterface(finder, interfaceName, -1), nil
}

func platformBindInterfaceControl(platform adapter.PlatformInterface, interfaceName string) (control.Func, error) {
	binder, ok := platform.(adapter.PlatformInterfaceBinder)
	if !ok {
		return nil, E.New("Android named interface binding requires a platform socket binder")
	}
	return func(_, _ string, conn syscall.RawConn) error {
		var bindErr error
		if err := conn.Control(func(fd uintptr) {
			bindErr = binder.BindInterfaceControl(int(fd), interfaceName)
		}); err != nil {
			return err
		}
		return bindErr
	}, nil
}
