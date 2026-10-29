//go:build !windows

package originca

// The sharing-violation branch is Windows-only; Unix requires rename success.
func runtimeRootRenameIsSharingViolation(error) bool { return false }
