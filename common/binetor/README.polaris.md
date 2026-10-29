# Local bine Tor package corrections

This package is based on the five files from cretz/bine v0.2.0 tor/, with its MIT license. UPSTREAM.json preserves the original commit, blobs and hashes separately from the current local patched-file hashes. Process/control/torutil remain the existing pinned v0.2.0 dependency; no module-cache source is patched.

Local differences are:

- tor.go captures the original process argument before Close clears Tor.Process. Control dialing uses its context; cancellation closes the actual saved control socket and joins its cancellation callback. SetConf errors propagate. The caller still owns actual process completion; the upstream 300 ms observer is not a completion guarantee.
- dialer.go normalizes one error message's capitalization.
- listen.go retains local error wording, ED25519 case ordering and maps.Copy usage. ED25519Key literals name KeyPair explicitly for vet and to preserve field identity.
- log.go uses any in place of interface{}.

doc.go and LICENSE match upstream. The manifest records source identity, not a claim of native validation or process completion.
