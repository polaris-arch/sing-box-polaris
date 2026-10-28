package tun

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

// Windows address-family values. NativeTun passes these to winipcfg unchanged.
const (
	windowsDNSIPv4 uint16 = 2
	windowsDNSIPv6 uint16 = 23
)

type windowsAddressDNSOperations struct {
	setAddresses func(uint16, []netip.Prefix) error
	resolveDNS   func(*Options, uint16) ([]netip.Addr, error)
	setDNS       func(uint16, []netip.Addr, []string) error
}

func resolveWindowsDNSAddress(options *Options, family uint16) ([]netip.Addr, error) {
	if family == windowsDNSIPv4 {
		return options.Inet4DNSAddress()
	}
	return options.Inet6DNSAddress()
}

// configureWindowsAddressesAndDNS preserves IPv4-before-IPv6 failure ordering.
// AutoRoute=false still configures addresses and clears the interface DNS list.
func configureWindowsAddressesAndDNS(options *Options, operations windowsAddressDNSOperations) error {
	if options.EXP_ExternalConfiguration {
		return nil
	}
	for _, family := range []struct {
		value     uint16
		name      string
		addresses []netip.Prefix
	}{
		{windowsDNSIPv4, "ipv4", options.Inet4Address},
		{windowsDNSIPv6, "ipv6", options.Inet6Address},
	} {
		if len(family.addresses) == 0 {
			continue
		}
		if err := operations.setAddresses(family.value, family.addresses); err != nil {
			return E.Cause(err, "set ", family.name, " address")
		}
		var dnsServers []netip.Addr
		if options.AutoRoute && options.DNSModeOrDefault() != DNSModeDisabled {
			var err error
			dnsServers, err = operations.resolveDNS(options, family.value)
			if err != nil {
				return err
			}
		}
		if err := operations.setDNS(family.value, dnsServers, nil); err != nil {
			return E.Cause(err, "set ", family.name, " dns")
		}
	}
	return nil
}
