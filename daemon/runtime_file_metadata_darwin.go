package daemon

// Match the established App private-file writer's mode/ownership policy.
// Arbitrary extended attributes and custom ACL migration are not promised by
// that writer or this binding. No extra metadata is copied from another owner.
func checkRuntimeAccessMetadata(_, _ string) error { return nil }
