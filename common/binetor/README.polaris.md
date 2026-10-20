# Narrow bine Tor package correction

This package is the five files from cretz/bine v0.2.0 tor/, with its MIT license. UPSTREAM.json records exact source blobs and SHA-256 hashes. Only the process argument capture in Tor.Close is changed. A late goroutine no longer reads the mutable Tor.Process field after Close clears it. The caller still owns actual process completion; the upstream 300 ms observer is not a completion guarantee. Process/control/torutil imports remain the existing v0.2.0 module.

No new module version, default transport, process execution, or native validation is introduced.
