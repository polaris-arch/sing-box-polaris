//go:build with_tailscale

package tailscale

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/tailscale/ipn"
)

type retirementMockStore struct {
	writes atomic.Int32
	write  func() error
}

func (*retirementMockStore) ReadState(ipn.StateKey) ([]byte, error) { return nil, ipn.ErrStateNotExist }

func (s *retirementMockStore) WriteState(ipn.StateKey, []byte) error {
	s.writes.Add(1)
	if s.write != nil {
		return s.write()
	}
	return nil
}

func waitStoreSealed(t *testing.T, s *guardedStateStore) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !s.isSealed() {
		if time.Now().After(deadline) {
			t.Fatal("seal was not published")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTailscaleStoreLazyConstructionLeaseAndLateWrites(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "not-created")
	entered, release := make(chan struct{}), make(chan struct{})
	mock := &retirementMockStore{}
	binding := adapter.TailscaleStoreRunBinding{RunNonce: "original", ConfigDigest: "actual"}
	ctx := service.ContextWithPtr(context.Background(), &binding)
	store := newGuardedStateStore(ctx, "target", directory, func() (ipn.StateStore, error) {
		close(entered)
		<-release
		if err := os.Mkdir(directory, 0o700); err != nil {
			return nil, err
		}
		// Model NewFileStore's synchronous initial write before its return.
		if err := os.WriteFile(filepath.Join(directory, "tailscaled.state"), []byte("{}"), 0o600); err != nil {
			return nil, err
		}
		return mock, nil
	})
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("eager constructor touched directory: %v", err)
	}
	written := make(chan error, 1)
	go func() { written <- store.WriteState("active", []byte("first")) }()
	<-entered
	retired := make(chan adapter.TailscaleStoreNode, 1)
	go func() { retired <- store.retire(time.Now().Add(time.Second), nil) }()
	waitStoreSealed(t, store)
	select {
	case <-retired:
		t.Fatal("constructor lease was not drained")
	default:
	}
	if err := store.WriteState("late", nil); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late write = %v", err)
	}
	close(release)
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	node := <-retired
	if node.WriterState != "SealedDrained" || node.RunNonce != "original" || node.ConfigDigest != "actual" || node.StateFileState != "Regular" {
		t.Fatalf("original binding/terminal lost: %+v", node)
	}
	if mock.writes.Load() != 1 {
		t.Fatalf("late delegate writes = %d", mock.writes.Load())
	}
	if err := store.WriteState("later", nil); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if again := store.retire(time.Now().Add(time.Second), nil); !reflect.DeepEqual(node, again) {
		t.Fatal("terminal changed")
	}
}

func TestTailscaleStoreWriteTimeoutStaysUnknownAfterLateCompletion(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	mock := &retirementMockStore{write: func() error { close(entered); <-release; return nil }}
	store := newGuardedStateStore(context.Background(), "target", t.TempDir(), func() (ipn.StateStore, error) { return mock, nil })
	written := make(chan error, 1)
	go func() { written <- store.WriteState("active", nil) }()
	<-entered
	node := store.retire(time.Now().Add(20*time.Millisecond), nil)
	if node.WriterState != "Unknown" {
		t.Fatalf("blocked write became positive: %+v", node)
	}
	close(release)
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if again := store.retire(time.Now().Add(time.Second), nil); !reflect.DeepEqual(node, again) {
		t.Fatal("late completion upgraded Unknown")
	}
	if err := store.WriteState("late", nil); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if mock.writes.Load() != 1 {
		t.Fatal("late write reached delegate")
	}
}

func TestTailscaleStoreNoConstructionFailureAndPanic(t *testing.T) {
	t.Run("no-construction", func(t *testing.T) {
		calls := 0
		store := newGuardedStateStore(context.Background(), "target", filepath.Join(t.TempDir(), "lazy"), func() (ipn.StateStore, error) { calls++; return &retirementMockStore{}, nil })
		node := store.retire(time.Now().Add(time.Second), nil)
		if calls != 0 || node.WriterState != "NoStoreConstruction" || node.StateFileState != "Missing" || node.ProfileState != "None" {
			t.Fatalf("not exact lazy non-construction: %+v / %d", node, calls)
		}
		endpoint := &Endpoint{stateStore: store}
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
		if err := endpoint.Start(adapter.StartStateInitialize, scope); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Start after seal = %v", err)
		}
		// No server/TUN/backend was initialized. The construction cleanup
		// only retires the Store and repeats the terminal it already reached.
		if err := endpoint.retireStateStore(); err != nil {
			t.Fatalf("construction cleanup after retirement = %v", err)
		}
		if err := scope.Close(); err != nil {
			t.Fatalf("sealed endpoint registered runtime cleanup: %v", err)
		}
	})
	for _, kind := range []string{"failure", "panic"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			store := newGuardedStateStore(context.Background(), "target", directory, func() (ipn.StateStore, error) {
				os.WriteFile(filepath.Join(directory, "tailscaled.state"), []byte("partial"), 0o600)
				if kind == "panic" {
					panic("original constructor panic")
				}
				return nil, errors.New("sensitive synthetic constructor failure")
			})
			func() {
				defer func() {
					r := recover()
					if kind == "panic" && r != "original constructor panic" {
						t.Fatalf("panic lost: %v", r)
					}
				}()
				_, err := store.ReadState("any")
				if kind == "failure" && err == nil {
					t.Fatal("failed factory accepted")
				}
			}()
			node := store.retire(time.Now().Add(time.Second), nil)
			if node.WriterState != "Unknown" {
				t.Fatalf("partial factory certified: %+v", node)
			}
			if err := store.WriteState("late", nil); !errors.Is(err, os.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

func TestSealedStoreStartDoesNotAcquireDirectory(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "not-created")
	store := newGuardedStateStore(ctx, "sealed", directory, func() (ipn.StateStore, error) {
		t.Fatal("Start constructed a sealed Store")
		return nil, nil
	})
	store.retire(time.Now().Add(time.Second), nil)
	owner := newDirectoryOwner(ctx, "sealed", directory)
	owner.managedPaths = true
	endpoint := &Endpoint{stateStore: store, directory: owner}
	for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart, adapter.StartStatePostStart} {
		if err := endpoint.Start(stage, nil); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("sealed Start stage %v = %v", stage, err)
		}
	}
	if owner.ready() || owner.lease != nil {
		t.Fatal("sealed Start acquired a directory lease")
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sealed Start touched the managed directory: %v", err)
	}
}

func profileStateBytes(t *testing.T, id, key string) []byte {
	t.Helper()
	profiles, err := json.Marshal(map[string]ipn.LoginProfile{id: {ID: ipn.ProfileID(id), Key: ipn.StateKey(key)}})
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]string{"_current-profile": base64.StdEncoding.EncodeToString([]byte(key)), "_profiles": base64.StdEncoding.EncodeToString(profiles), "_taildrop-received": base64.StdEncoding.EncodeToString([]byte("keep-user-data"))}
	content, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestTailscaleStoreRealFileProfileAndLateObserver(t *testing.T) {
	for _, kind := range []string{"bound", "failed-write-cache", "late-observer", "no-original-backend"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			content := profileStateBytes(t, "old-id", "profile-old")
			if err := os.WriteFile(filepath.Join(directory, "tailscaled.state"), content, 0o600); err != nil {
				t.Fatal(err)
			}
			store := newGuardedStateStore(context.Background(), "target", directory, func() (ipn.StateStore, error) {
				return &retirementMockStore{write: func() error { return errors.New("simulated cache changed but atomic write failed") }}, nil
			})
			if err := store.WriteState("profile-new", nil); err == nil {
				t.Fatal("mock write unexpectedly succeeded")
			}
			profile := func() (string, string) { return "old-id", "profile-old" }
			release := make(chan struct{})
			returned := make(chan struct{})
			switch kind {
			case "failed-write-cache":
				profile = func() (string, string) { return "new-id", "profile-new" }
			case "late-observer":
				profile = func() (string, string) { <-release; close(returned); return "old-id", "profile-old" }
			case "no-original-backend":
				profile = nil
			}
			deadline := time.Now().Add(time.Second)
			if kind == "late-observer" {
				deadline = time.Now().Add(25 * time.Millisecond)
			}
			node := store.retire(deadline, profile)
			if node.WriterState != "SealedDrained" || node.StateFileState != "Regular" {
				t.Fatalf("store/file facts lost: %+v", node)
			}
			digest := sha256.Sum256(content)
			if node.StateFileRevision != hex.EncodeToString(digest[:]) {
				t.Fatal("revision did not hash actual file")
			}
			if kind == "bound" {
				// Use actual NUL delimiters, not source-escaped backslash bytes.
				fingerprint := sha256.Sum256(bytes.Join([][]byte{[]byte("polaris-ts-profile-v1"), []byte("old-id"), []byte("profile-old")}, []byte{0}))
				if node.ProfileState != "Bound" || node.ProfileFingerprint != hex.EncodeToString(fingerprint[:]) {
					t.Fatalf("original profile not bound: %+v", node)
				}
			} else if node.ProfileState != "Unknown" || node.ProfileFingerprint != "" {
				t.Fatalf("stale observer/cache certified: %+v", node)
			}
			if kind == "late-observer" {
				close(release)
				<-returned
				if again := store.retire(time.Now().Add(time.Second), profile); !reflect.DeepEqual(node, again) {
					t.Fatal("late metadata upgraded Unknown")
				}
			}
			after, err := os.ReadFile(filepath.Join(directory, "tailscaled.state"))
			if err != nil || !bytes.Equal(after, content) {
				t.Fatal("export rewrote target or Taildrop state")
			}
		})
	}
}

func TestTailscaleStoreCanonicalFactoryAndUnsafeFile(t *testing.T) {
	// macOS temporary roots include /var -> /private/var. Canonicalize the
	// fixture root independently; keep retargeted-alias/unsafe-file checks.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	for _, path := range []string{a, b} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(a, alias); err != nil {
		t.Fatal(err)
	}
	store := makeStateStore(context.Background(), "target", alias)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadState("none"); !errors.Is(err, ipn.ErrStateNotExist) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(a, "tailscaled.state")); err != nil {
		t.Fatal("factory lost pinned canonical scope", err)
	}
	if _, err := os.Stat(filepath.Join(b, "tailscaled.state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("factory wrote retargeted alias", err)
	}
	node := store.retire(time.Now().Add(time.Second), nil)
	if node.StateDirectory != a || node.WriterState != "SealedDrained" {
		t.Fatalf("canonical scope lost: %+v", node)
	}
	for _, kind := range []string{"symlink", "oversize", "directory"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "tailscaled.state")
			switch kind {
			case "symlink":
				if err := os.Symlink(filepath.Join(a, "tailscaled.state"), path); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				file, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = file.Truncate(maxStateStoreBytes + 1); err != nil {
					t.Fatal(err)
				}
				file.Close()
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			guard := newGuardedStateStore(context.Background(), "target", directory, func() (ipn.StateStore, error) { t.Fatal("unadmitted unsafe file initialized"); return nil, nil })
			result := guard.retire(time.Now().Add(time.Second), nil)
			if result.StateFileState != "Unknown" || result.ProfileState != "Unknown" || result.StateFileRevision != "" {
				t.Fatalf("unsafe data accepted: %+v", result)
			}
		})
	}
}

// Load through the pinned SDK's real FileStore and LoginProfileView codec.
// No tsnet server, network observer or real backend is started.
func TestTailscaleStorePinnedSDKProjectionFixture(t *testing.T) {
	content, err := os.ReadFile("testdata/synthetic-sealed-state.json")
	if err != nil {
		t.Fatal(err)
	}
	expectedBytes, err := os.ReadFile("testdata/synthetic-sealed-state.expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected struct{ ProfileFingerprint, StateFileRevision string }
	if err := json.Unmarshal(expectedBytes, &expected); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "tailscaled.state")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	guard := makeStateStore(context.Background(), "target", directory)
	current, err := guard.ReadState(ipn.CurrentProfileStateKey)
	if err != nil {
		t.Fatal(err)
	}
	profilesBytes, err := guard.ReadState(ipn.KnownProfilesStateKey)
	if err != nil {
		t.Fatal(err)
	}
	var profiles map[ipn.ProfileID]ipn.LoginProfileView
	if err := json.Unmarshal(profilesBytes, &profiles); err != nil {
		t.Fatal(err)
	}
	profile := profiles[ipn.ProfileID("a123")]
	if !profile.Valid() || string(profile.Key()) != string(current) {
		t.Fatal("fixture does not match real SDK references")
	}
	node := guard.retire(time.Now().Add(time.Second), func() (string, string) { return string(profile.ID()), string(profile.Key()) })
	if node.ProfileState != "Bound" || node.ProfileFingerprint != expected.ProfileFingerprint || node.StateFileRevision != expected.StateFileRevision {
		t.Fatalf("codec/fingerprint/revision drift: %+v", node)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, after) {
		t.Fatal("read-only retirement changed synthetic preserved values")
	}
}

func TestTailscaleStoreExpiredDeadlineCannotWinReadySelect(t *testing.T) {
	for range 20 {
		store := newGuardedStateStore(context.Background(), "target", t.TempDir(), func() (ipn.StateStore, error) { t.Fatal("expired retirement initialized store"); return nil, nil })
		node := store.retire(time.Now().Add(-time.Millisecond), nil)
		if node.WriterState != "Unknown" || node.StateFileState != "Unknown" {
			t.Fatalf("ready drained channel defeated expired deadline: %+v", node)
		}
		if err := store.WriteState("late", nil); !errors.Is(err, os.ErrClosed) {
			t.Fatal(err)
		}
	}
}

func TestTailscaleStoreConstructionObserverOriginalGuardAndLateAdmission(t *testing.T) {
	var captured []func(time.Time) adapter.TailscaleStoreNode
	var closed bool
	observer := adapter.TailscaleStoreConstructionObserver{Observe: func(node adapter.TailscaleStoreNode, retire func(time.Time) adapter.TailscaleStoreNode) bool {
		if closed {
			return false
		}
		if node.RunNonce != "original-observer" || node.ConfigDigest != "actual-input" {
			t.Fatal("guard lost original context binding")
		}
		captured = append(captured, retire)
		return true
	}}
	binding := adapter.TailscaleStoreRunBinding{RunNonce: "original-observer", ConfigDigest: "actual-input"}
	ctx := service.ContextWithPtr(context.Background(), &binding)
	ctx = service.ContextWithPtr(ctx, &observer)
	calls := 0
	store := newGuardedStateStore(ctx, "target", filepath.Join(t.TempDir(), "lazy"), func() (ipn.StateStore, error) { calls++; return &retirementMockStore{}, nil })
	if len(captured) != 1 || calls != 0 || store.isSealed() {
		t.Fatal("observer eagerly constructed or sealed original guard")
	}
	closed = true
	original := captured[0](time.Now().Add(time.Second))
	if original.WriterState != "NoStoreConstruction" || !store.isSealed() || calls != 0 {
		t.Fatalf("observer did not retire same original guard: %+v", original)
	}
	late := newGuardedStateStore(ctx, "late", filepath.Join(t.TempDir(), "late"), func() (ipn.StateStore, error) { calls++; return &retirementMockStore{}, nil })
	if !late.isSealed() {
		t.Fatal("late actual guard returned before permanent seal")
	}
	if _, err := late.ReadState("late"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late read admitted: %v", err)
	}
	if err := late.WriteState("late", nil); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late write admitted: %v", err)
	}
	if calls != 0 || len(captured) != 1 {
		t.Fatal("late factory or observation was admitted")
	}
	if again := late.retire(time.Now().Add(time.Second), nil); again.WriterState != "NoStoreConstruction" {
		t.Fatalf("late seal could not be retired idempotently: %+v", again)
	}
}

func TestTailscaleStoreConstructionObserverPanicRejectsHandoff(t *testing.T) {
	observer := adapter.TailscaleStoreConstructionObserver{Observe: func(adapter.TailscaleStoreNode, func(time.Time) adapter.TailscaleStoreNode) bool {
		panic("synthetic observer failure")
	}}
	ctx := service.ContextWithPtr(context.Background(), &observer)
	factoryCalls := 0
	returned := false
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("observer panic swallowed")
			}
		}()
		newGuardedStateStore(ctx, "original", t.TempDir(), func() (ipn.StateStore, error) { factoryCalls++; return &retirementMockStore{}, nil })
		returned = true
	}()
	if returned || factoryCalls != 0 {
		t.Fatal("panicking observer handed off or admitted a guard")
	}
}
