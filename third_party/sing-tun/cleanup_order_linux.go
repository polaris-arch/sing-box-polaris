package tun

import (
	"errors"
	"io"
)

// Network cleanup must not be queued behind a resolver subprocess. Preserve all
// cleanup errors and always close the device, including when DNS revert times out.
func closeNativeTunResources(network, dns, device func() error) error {
	networkErr := network()
	dnsErr := dns()
	deviceErr := device()
	return errors.Join(networkErr, dnsErr, deviceErr)
}

// Close the os.File owner rather than its raw descriptor. Otherwise its later
// finalizer may close an unrelated descriptor that reused the same number.
func failNativeTunConstruction(cause error, file io.Closer) error {
	return errors.Join(cause, file.Close())
}
