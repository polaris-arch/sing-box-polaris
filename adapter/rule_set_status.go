package adapter

// Optional read-only capability. ActiveDigest describes accepted bytes, not the
// file currently on disk. An empty digest is not an acknowledgement.
type RuleSetLoadStatus struct {
	ActiveDigest string
	Revision     uint64
	WatcherState string
	LastError    string
	Closed       bool
}
type RuleSetStatusProvider interface{ RuleSetStatus() RuleSetLoadStatus }
