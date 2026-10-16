//go:build unix

package libbox

import "testing"

// Only the Unix mobile platform projects native link flags via NetworkInterfaces.
// Keep this check on the same successor fixture after every generic lifecycle check.
func assertSuccessorNetworkProjection(t *testing.T, w *platformInterfaceWrapper) {
	t.Helper()
	projected, err := w.NetworkInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(projected) != 1 || !projected[0].Expensive || !projected[0].Constrained {
		t.Fatalf("successor projection changed: %+v", projected)
	}
}
