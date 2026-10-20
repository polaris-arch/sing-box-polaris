package tor

import (
	"sort"

	"github.com/sagernet/sing-box/option"
)

// RuntimeOverlapProblem describes whether a NEW process may be staged while
// older generations are still serving admitted streams. It is not a blanket
// protocol eligibility check: an unchanged resource may be reused even when
// this function reports an exclusive configuration. The coordinator must apply
// this check to the actual construction set, including dependency replacements.
//
// The zero-value App Tor settings use bine's private temporary DataDirectory,
// auto SOCKS listener and auto control listener. The proxy bridge also binds an
// ephemeral port. No persistent identity or fixed listener is then shared.
// Do not rewrite a user's persistent directory into a temporary directory: it
// can contain durable Tor identity/state whose semantics must be preserved.
func RuntimeOverlapProblem(options option.TorOutboundOptions) (field, reason string) {
	if options.DataDirectory != "" {
		return "data_directory", "Tor replacement requires exclusive persistent data-directory ownership; retained process may still own its lock, state, and torrc"
	}
	if len(options.ExtraArgs) != 0 {
		return "extra_args", "Tor launch arguments may override data, control, listeners, or configuration files; overlapping process construction is not certified"
	}
	keys := make([]string, 0, len(options.Options))
	for key := range options.Options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch key {
		case "Socks5Proxy", "Socks5ProxyUsername", "Socks5ProxyPassword":
			// start ignores these exact keys in favor of the private bridge.
			// Case variants are not ignored and must not inherit this proof.
			continue
		default:
			return "torrc." + key, "custom Tor configuration may acquire fixed listeners, control endpoints, or persistent paths; overlapping process construction is not certified"
		}
	}
	// ExecutablePath selects the existing process creator and does not itself
	// choose a shared directory or port. Process lifetime still uses the actual
	// Start/Wait owner; the executable must obey the existing Tor CLI contract.
	return "", ""
}
