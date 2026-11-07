//go:build windows

package box

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func clientShapeIPv6CollisionHolder(t *testing.T, port int) net.Listener {
	t.Helper()
	const exclusiveAddrUse = ^int(windows.SO_REUSEADDR)
	config := net.ListenConfig{
		Control: func(network, _ string, raw syscall.RawConn) error {
			if network != "tcp6" {
				return fmt.Errorf("IPv6-only collision holder received network %q", network)
			}
			var socketErr error
			err := raw.Control(func(fd uintptr) {
				handle := windows.Handle(fd)
				socketErr = windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1)
				if socketErr == nil {
					socketErr = windows.SetsockoptInt(handle, windows.SOL_SOCKET, exclusiveAddrUse, 1)
				}
			})
			if err != nil {
				return err
			}
			return socketErr
		},
	}
	holder, err := config.Listen(context.Background(), "tcp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		t.Fatal("bind exclusive IPv6 collision holder", err)
	}
	verified := false
	defer func() {
		if !verified {
			_ = holder.Close()
		}
	}()
	raw, err := holder.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v6only, exclusive int
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		v6only, socketErr = windows.GetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
		if socketErr == nil {
			exclusive, socketErr = windows.GetsockoptInt(handle, windows.SOL_SOCKET, exclusiveAddrUse)
		}
	})
	if err != nil || socketErr != nil {
		t.Fatal("read bound collision holder socket options", err, socketErr)
	}
	if v6only != 1 || exclusive == 0 {
		t.Fatal("bound holder lacks IPv6-only exclusive custody", v6only, exclusive)
	}
	t.Logf("bound IPv6 collision holder %s: IPV6_V6ONLY=%d SO_EXCLUSIVEADDRUSE=%d", holder.Addr(), v6only, exclusive)
	verified = true
	return holder
}
