//go:build !windows

package listener

import (
	"net"
	"net/netip"
)

func (l *Listener) runtimeTCPWildcardNetwork(_ *net.ListenConfig, network string, _ netip.Addr) string {
	return network
}

func (l *Listener) validateRuntimeTCPWildcard(_ string, _ net.Listener) error { return nil }
