package libbox

import "github.com/sagernet/sing-box/common/tls"

// TLSFingerprintCapabilities is the same JSON contract exposed by the desktop
// tls-fingerprints command. A mobile caller must query the actually loaded core.
func TLSFingerprintCapabilities() (string, error) {
	return tls.FingerprintCapabilitiesJSON()
}
