//go:build darwin || linux || windows

package libbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeSnapshotPrepareFailurePreservesPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configuration.json")
	old := []byte(`{"old":true}`)
	if err := os.WriteFile(path, old, 0600); err != nil { t.Fatal(err) }
	failure := errors.New("prepare denied")
	err := writeRuntimeConfigSnapshot(path, []byte(`{"new":true}`), func(*os.File) error { return failure })
	if !errors.Is(err, failure) { t.Fatalf("got %v", err) }
	content, err := os.ReadFile(path)
	if err != nil || string(content) != string(old) { t.Fatalf("old snapshot changed: %q, %v", content, err) }
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 { t.Fatalf("temporary leak: %v, %v", entries, err) }
}

func TestRuntimeSnapshotPublishesDetachedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configuration.json")
	content := []byte(`{"literal":"$value 'quote' $(inert)"}`)
	err := writeRuntimeConfigSnapshot(path, content, nil)
	actual, readErr := os.ReadFile(path)
	if readErr != nil || string(actual) != string(content) { t.Fatalf("snapshot mismatch: %q, %v (write %v)", actual, readErr, err) }
	// Some target filesystems cannot sync directory handles. In that case the
	// callback correctly reports uncertainty despite a visible complete file.
	if err != nil { t.Logf("directory durability was not certified: %v", err) }
}
