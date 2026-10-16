//go:build !unix

package libbox

import "testing"

func assertSuccessorNetworkProjection(t *testing.T, _ *platformInterfaceWrapper) {
	t.Helper()
	// NetworkInterfaces uses a deliberately unsupported native linkFlags stub
	// here. Only that Unix projection is inapplicable; the common caller still
	// asserts identity, expensive/constrained snapshot, old-callback isolation,
	// lifecycle and in-flight accounting. Do not skip the test or fake flags.
}
