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
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/windows"
)

func (l *Listener) runtimeTCPPlatformSpecs() []runtimeTCPBindSpec {
	address := l.listenOptions.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1}))
	spec := runtimeTCPBindSpec{network: M.NetworkFromNetAddr("tcp", address), address: address, port: l.listenOptions.ListenPort, netns: l.listenOptions.NetNs, exclusive: l.exclusive}
	if address != netip.IPv6Unspecified() {
		return []runtimeTCPBindSpec{spec}
	}
	if l.exclusive {
		// Preserve the explicit API/control-plane dual-stack exclusive policy.
		spec.network = "tcp6"
		return []runtimeTCPBindSpec{spec}
	}
	v6 := spec
	v6.network = "tcp6"
	v6.v6only = true
	v6.exclusive = true
	v6.narrowExclusive = true
	v4 := spec
	v4.network = "tcp4"
	v4.address = netip.IPv4Unspecified()
	// First bind is the real IPv6 owner, never a probe. This detects an IPv6
	// collision before touching any old ordinary IPv4 listening descriptor.
	return []runtimeTCPBindSpec{v6, v4}
}

func (l *Listener) validateRuntimeTCPPolicy() error {
	if !l.exclusive && l.listenOptions.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})) == netip.IPv6Unspecified() && l.listenOptions.ReuseAddr {
		return errors.New("runtime IPv6 wildcard exclusive member cannot enable reuse_addr")
	}
	return nil
}

func (l *Listener) controlRuntimeTCPMember(config *net.ListenConfig, spec runtimeTCPBindSpec) error {
	if spec.address != netip.IPv6Unspecified() {
		return nil
	}
	config.Control = control.Append(config.Control, func(network, _ string, raw syscall.RawConn) error {
		if network != "tcp6" {
			return fmt.Errorf("runtime IPv6 wildcard received network %q", network)
		}
		return control.Raw(raw, func(fd uintptr) error {
			handle := windows.Handle(fd)
			want := 0
			if spec.v6only {
				want = 1
			}
			if err := windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, want); err != nil {
				return os.NewSyscallError("setsockopt(IPV6_V6ONLY)", err)
			}
			if spec.narrowExclusive {
				if err := windows.SetsockoptInt(handle, windows.SOL_SOCKET, ^int(windows.SO_REUSEADDR), 1); err != nil {
					return os.NewSyscallError("setsockopt(SO_EXCLUSIVEADDRUSE)", err)
				}
			}
			value, err := windows.GetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
			if err != nil {
				return os.NewSyscallError("getsockopt(IPV6_V6ONLY)", err)
			}
			if value != want {
				return errors.New("runtime IPv6 wildcard lost requested family policy before bind")
			}
			return nil
		})
	})
	return nil
}

func (l *Listener) validateRuntimeTCPMember(member *runtimeTCPMember) error {
	spec, socket := member.spec, member.socket
	split := !l.exclusive && l.listenOptions.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})) == netip.IPv6Unspecified()
	if spec.address != netip.IPv6Unspecified() && !(split && spec.network == "tcp4" && spec.address == netip.IPv4Unspecified()) {
		return nil
	}
	conn, ok := socket.(syscall.Conn)
	if !ok {
		return errors.New("runtime wildcard member has no native socket readback")
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
		var localPort int
		v6only := -1
		switch local := address.(type) {
		case *windows.SockaddrInet6:
			if spec.network != "tcp6" || spec.address != netip.IPv6Unspecified() || local.Addr != [16]byte{} || local.ZoneId != 0 {
				return errors.New("runtime wildcard member differs from requested IPv6 family/tuple")
			}
			localPort = local.Port
			v6only, err = windows.GetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
			if err != nil {
				return os.NewSyscallError("getsockopt(IPV6_V6ONLY)", err)
			}
			want := 0
			if spec.v6only {
				want = 1
			}
			if v6only != want {
				return errors.New("runtime wildcard member differs from requested IPv6-only policy")
			}
		case *windows.SockaddrInet4:
			if spec.network != "tcp4" || spec.address != netip.IPv4Unspecified() || local.Addr != [4]byte{} {
				return errors.New("runtime wildcard member differs from requested IPv4 family/tuple")
			}
			localPort = local.Port
		default:
			return errors.New("runtime wildcard member has unexpected native family")
		}
		reuse, err := windows.GetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_REUSEADDR)
		if err != nil {
			return os.NewSyscallError("getsockopt(SO_REUSEADDR)", err)
		}
		exclusive, err := windows.GetsockoptInt(handle, windows.SOL_SOCKET, ^int(windows.SO_REUSEADDR))
		if err != nil {
			return os.NewSyscallError("getsockopt(SO_EXCLUSIVEADDRUSE)", err)
		}
		l.logger.Debug("Windows runtime TCP member network=", spec.network, " local=", socket.Addr(), " IPV6_V6ONLY=", v6only, " SO_REUSEADDR=", reuse, " SO_EXCLUSIVEADDRUSE=", exclusive)
		if localPort == 0 || localPort != int(spec.port) {
			return errors.New("runtime wildcard member differs from requested port")
		}
		if spec.narrowExclusive || !l.exclusive && spec.network == "tcp4" {
			if reuse != 0 || (exclusive != 0) != spec.exclusive {
				return errors.New("runtime wildcard member differs from requested exclusive custody")
			}
		}
		return nil
	})
}
