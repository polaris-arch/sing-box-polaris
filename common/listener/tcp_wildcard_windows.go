//go:build windows

package listener

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/windows"
)

// An explicit runtime :: must retain both native IPv6 and mapped IPv4. Passing
// tcp lets Go choose IPv4zero when its mapped-IPv4 capability probe is false.
func (l *Listener) runtimeTCPWildcardNetwork(config *net.ListenConfig, network string, address netip.Addr) string {
	if l.runtime == nil || address != netip.IPv6Unspecified() {
		return network
	}
	config.Control = control.Append(config.Control, func(network, _ string, raw syscall.RawConn) error {
		if network != "tcp6" {
			return fmt.Errorf("runtime IPv6 wildcard received network %q", network)
		}
		return control.Raw(raw, func(fd uintptr) error {
			handle := windows.Handle(fd)
			if err := windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 0); err != nil {
				return os.NewSyscallError("setsockopt(IPV6_V6ONLY)", err)
			}
			value, err := windows.GetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
			if err != nil {
				return os.NewSyscallError("getsockopt(IPV6_V6ONLY)", err)
			}
			if value != 0 {
				return errors.New("runtime IPv6 wildcard lost mapped IPv4 before bind")
			}
			return nil
		})
	})
	// tcp6 fixes AF_INET6; Control above clears Go's IPv6-only default before
	// the actual bind. Merely selecting tcp6 would remove IPv4 allowLAN.
	return "tcp6"
}

func (l *Listener) validateRuntimeTCPWildcard(network string, socket net.Listener) error {
	if l.runtime == nil || l.listenOptions.Listen == nil || netip.Addr(*l.listenOptions.Listen) != netip.IPv6Unspecified() {
		return nil
	}
	if network != "tcp6" {
		return errors.New("runtime IPv6 wildcard did not retain its IPv6 socket family")
	}
	// Both net.ListenConfig and the vendored Windows TFO listener return a
	// *net.TCPListener. Keep the descriptor private to the owning listener.
	conn, ok := socket.(syscall.Conn)
	if !ok {
		return errors.New("runtime IPv6 wildcard has no native socket readback")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return control.Raw(raw, func(fd uintptr) error {
		handle := windows.Handle(fd)
		address, err := windows.Getsockname(handle)
		if err != nil {
			return os.NewSyscallError("getsockname", err)
		}
		local, ok := address.(*windows.SockaddrInet6)
		if !ok {
			return errors.New("bound runtime IPv6 wildcard is not AF_INET6")
		}
		v6only, err := windows.GetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
		if err != nil {
			return os.NewSyscallError("getsockopt(IPV6_V6ONLY)", err)
		}
		reuse, err := windows.GetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_REUSEADDR)
		if err != nil {
			return os.NewSyscallError("getsockopt(SO_REUSEADDR)", err)
		}
		exclusive, err := windows.GetsockoptInt(handle, windows.SOL_SOCKET, ^int(windows.SO_REUSEADDR))
		if err != nil {
			return os.NewSyscallError("getsockopt(SO_EXCLUSIVEADDRUSE)", err)
		}
		l.logger.Debug("Windows runtime TCP binding family=AF_INET6 network=", network,
			" local=", net.JoinHostPort(netip.AddrFrom16(local.Addr).String(), fmt.Sprint(local.Port)),
			" IPV6_V6ONLY=", v6only, " SO_REUSEADDR=", reuse, " SO_EXCLUSIVEADDRUSE=", exclusive)
		if local.Addr != [16]byte{} || local.ZoneId != 0 || local.Port == 0 ||
			l.listenOptions.ListenPort != 0 && local.Port != int(l.listenOptions.ListenPort) || v6only != 0 {
			return errors.New("bound runtime IPv6 wildcard differs from its requested dual-stack tuple")
		}
		return nil
	})
}
