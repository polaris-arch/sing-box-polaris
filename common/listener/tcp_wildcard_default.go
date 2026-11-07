//go:build !windows

package listener

import (
	"net"
	"net/netip"

	M "github.com/sagernet/sing/common/metadata"
)

func (l *Listener) runtimeTCPPlatformSpecs() []runtimeTCPBindSpec {
	address := l.listenOptions.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1}))
	return []runtimeTCPBindSpec{{network: M.NetworkFromNetAddr("tcp", address), address: address, port: l.listenOptions.ListenPort, netns: l.listenOptions.NetNs, exclusive: l.exclusive}}
}
func (l *Listener) validateRuntimeTCPPolicy() error { return nil }
func (l *Listener) controlRuntimeTCPMember(_ *net.ListenConfig, _ runtimeTCPBindSpec) error {
	return nil
}
func (l *Listener) validateRuntimeTCPMember(_ *runtimeTCPMember) error { return nil }
