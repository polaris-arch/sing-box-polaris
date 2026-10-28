//go:build !with_tailscale

package libbox

import "errors"

const tailscaleDirectoryDomainSupported = false

func poisonTailscaleDirectoryDomain(string) error {
	return errors.New("Tailscale directory domain unavailable")
}
