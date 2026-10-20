package openconnect

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-openconnect"
)

// Called only for actual replacement of an existing physical owner. Initial
// HOTP/fixed-port owners and unchanged retained owners remain valid.
func RuntimeReplacementProblem(options option.OpenConnectEndpointOptions) (field, reason string) {
	if options.System {
		return "system", "system device handoff requires restart"
	}
	if options.DTLSLocalPort != 0 {
		return "dtls_local_port", "fixed DTLS port coexistence requires restart"
	}
	if options.Token != nil && options.Token.Mode == openconnect.TokenModeHOTP {
		return "token.counter", "live consumed HOTP counter handoff requires restart"
	}
	return "", ""
}
