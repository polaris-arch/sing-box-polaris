//go:build with_tailscale

package tailscale

import (
	"context"
	"fmt"
	"github.com/sagernet/tailscale/util/dirscope"
	"path/filepath"
	"testing"
	"time"
)

func TestScopedStoreCannotConstructWithoutLease(t *testing.T) {
	s := makeStateStore(context.Background(), "node", filepath.Join(t.TempDir(), "absent"), new(dirscope.Scope))
	if _, err := s.factory(); err == nil {
		t.Fatal("factory admitted without lifetime lease")
	}
}

func TestNeverStartedScopedStoreDoesNotReadDirectory(t *testing.T) {
	s := makeStateStore(context.Background(), "node", filepath.Join(t.TempDir(), "absent"), new(dirscope.Scope))
	result := s.retire(time.Now().Add(time.Second), nil)
	if result.StateFileState != "Unknown" {
		t.Fatalf("unleased filesystem witness: %s", result.StateFileState)
	}
}

func TestTaildropRejectsIOBeforeDirectoryLease(t *testing.T) {
	m := &taildropManager{directoryReady: func() bool { return false }}
	if m.beginIO() {
		m.endIO()
		t.Fatal("Taildrop admitted without a directory lifetime lease")
	}
}

type failingTaildropCloser struct{ err error }

func (c failingTaildropCloser) Close() error { return c.err }

func TestTaildropCloseFailureStaysUnknownAfterActualDrain(t *testing.T) {
	m := newTaildropManager(context.Background(), nil, "node", t.TempDir(), nil)
	if !m.beginIO() {
		t.Fatal("admission failed")
	}
	failure := fmt.Errorf("injected close failure")
	if err := m.closeFile(failingTaildropCloser{failure}); err != failure {
		t.Fatal(err)
	}
	m.endIO()
	m.seal()
	<-m.drainDone
	if err := m.waitContext(context.Background()); err == nil {
		t.Fatal("actual drain erased close failure")
	}
}
