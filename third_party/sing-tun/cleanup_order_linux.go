package tun

import "errors"

// Network cleanup must not be queued behind a resolver subprocess. Preserve all
// cleanup errors and always close the device, including when DNS revert times out.
func closeNativeTunResources(network, dns, device func() error) error {
	networkErr := network()
	dnsErr := dns()
	deviceErr := device()
	return errors.Join(networkErr, dnsErr, deviceErr)
}
