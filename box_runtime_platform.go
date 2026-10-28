package box

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/route"
)

// Stable capabilities are those actually provisioned at initial startup, not
// the preceding revision's rule demand. Removing a rule does not remove the
// shared platform resource and cannot prevent a later rule from reusing it.
func runtimePlatformRequirementsAvailable(have, need route.RuntimeRequirements) bool {
	if need.Process && !have.Process && !runtimeCanPrepareProcessSearcher() || need.Neighbor && !have.Neighbor || need.WIFI && !have.WIFI {
		return false
	}
	files := make(map[string]bool, len(have.DHCPLeaseFiles))
	for _, path := range have.DHCPLeaseFiles {
		files[path] = true
	}
	for _, path := range need.DHCPLeaseFiles {
		if !files[path] {
			return false
		}
	}
	return true
}

// Only the reviewed desktop implementations may allocate the original private
// process searcher during candidate Start. Platform-provided mobile lookup must
// already have been provisioned; this does not grant new OS visibility.
func runtimeCanPrepareProcessSearcher() bool {
	return C.IsWindows || C.IsLinux && !C.IsAndroid || C.IsDarwin && !C.IsIos
}
