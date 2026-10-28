package masque

// RuntimeCleanupObservation exposes only finite source-defined states. It does
// not call the endpoint/device/native client or borrow a resource lease.
func (c *ClientEndpoint) RuntimeCleanupObservation() (uint32, bool) {
	if c.runtime == nil {
		return 0, false
	}
	return c.runtime.diagnosticPhase.Load(), c.runtime.diagnosticFailed.Load()
}
